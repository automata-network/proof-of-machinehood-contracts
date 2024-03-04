// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "./AttestationVerificationBase.sol";
import "../utils/BytesUtils.sol";

contract AndroidSafetyNet is AttestationVerificationBase {
    using BytesUtils for bytes;
    using JSONParserLib for JSONParserLib.Item;
    using LibString for string;

    string constant EXPECTED_TRUE = "true";

    struct AttStmt {
        ISigVerifyLib.Algorithm alg;
        // The JWT components should be based64 encoded string plus paddings
        string jwtHeader; // Based64URL encoded
        string jwtPayload; // Based64URL encoded
        string jwtSignature; // Base64 encoded
        // Certificate chain parsed from jwtHeader
        // In a scenario where the `x5c` field in the `jwtHeader` contains certificates 'a' and 'b', but the separately provided `x5c` contains 'a' and 'c', and both 'b' and 'c' are issued by the CA certificate, we allow the attestation verification to succeed.
        ISigVerifyLib.Certificate[] x5c;
    }

    constructor(address _sigVerify, address _derParser) {
        sigVerify = ISigVerifyLib(_sigVerify);
        derParser = IDerParser(_derParser);
        _initializeOwner(msg.sender);
    }

    function _verify(bytes memory attStmt, bytes memory authData, bytes memory clientData)
        internal
        view
        override
        returns (bool, string memory)
    {
        AttStmt memory decoded = abi.decode(attStmt, (AttStmt));

        // Step 1: Verify jwt signature
        {
            bytes memory tbs = abi.encodePacked(decoded.jwtHeader, ".", decoded.jwtPayload);
            bytes memory signatureBytes = Base64.decode(decoded.jwtSignature);
            bool validSig = sigVerify.verifyAttStmtSignature(tbs, signatureBytes, decoded.x5c[0].publicKey, decoded.alg);
            if (!validSig) {
                return (false, "invalid JWT sig");
            }
        }

        // Step 2: Verify jwt payload
        {
            string memory jwtPayloadJSON = string(Base64.decode(_base64UrlToBase64(decoded.jwtPayload)));
            JSONParserLib.Item memory root = JSONParserLib.parse(jwtPayloadJSON);
            JSONParserLib.Item[] memory content = root.children();

            bool validNonce;
            bool validCtsProfile;
            bool validBasicIntegrity;

            for (uint256 i = 0; i < root.size(); i++) {
                string memory decodedKey = JSONParserLib.decodeString(content[i].key());
                if (decodedKey.eq("nonce")) {
                    bytes32 clientDataHash = sha256(clientData);
                    bytes32 expectedNonce = sha256(abi.encodePacked(authData, clientDataHash));
                    string memory parsedNonce = JSONParserLib.decodeString(content[i].value());
                    bytes memory decodedNonce = Base64.decode(parsedNonce);
                    if (decodedNonce.length != 32 || expectedNonce != bytes32(decodedNonce)) {
                        return (false, "invalid JWT Payload");
                    }
                    validNonce = true;
                } else if (decodedKey.eq("ctsProfileMatch")) {
                    string memory value = content[i].value();
                    if (!value.eq(EXPECTED_TRUE)) {
                        return (false, "invalid JWT Payload");
                    }
                    validCtsProfile = true;
                } else if (decodedKey.eq("basicIntegrity")) {
                    string memory value = content[i].value();
                    if (!value.eq(EXPECTED_TRUE)) {
                        return (false, "invalid JWT Payload");
                    }
                    validBasicIntegrity = true;
                }
            }

            if (!validNonce || !validCtsProfile || !validBasicIntegrity) {
                return (false, "invalid JWT Payload");
            }
        }

        // Step 3: Verify cert chain in the jwtHeader
        {
            bool containsTrustedCACertificate = false;
            for (uint256 i = 0; i < decoded.x5c.length - 1; i++) {
                ISigVerifyLib.Certificate memory cert = decoded.x5c[i];
                ISigVerifyLib.Certificate memory fatherCert = decoded.x5c[i + 1];

                // Get the validity and altSubjectName of the certificate
                bool parseAltSubjectName = i == 0 ? true : false;
                (uint256 notBefore, uint256 notAfter, bytes memory subjectAltName) =
                    derParser.parseValidityAndAltSubjectName(cert.tbsCertificate, parseAltSubjectName);

                // Verify validity of the certificate
                if (notBefore > block.timestamp || notAfter < block.timestamp) {
                    return (false, "expired certificate");
                }

                // Verify altSubjectName if the certificate is the leaf certificate
                if (i == 0) {
                    // 0x82126174746573742e616e64726f69642e636f6d is the der encoding of "DNS: attest.android.com"
                    if (!BytesUtils.compareBytes(subjectAltName, hex"82126174746573742e616e64726f69642e636f6d")) {
                        return (false, "invalid leaf certificate altSubjectName");
                    }
                }

                // Verify the signature of the certificate
                bool validSig = sigVerify.verifyCertificateSignature(
                    cert.tbsCertificate, cert.signature, fatherCert.publicKey, cert.sigAlg
                );
                if (!validSig) {
                    return (false, "invalid certificate signature");
                }

                // Check whether the certificate is a trusted CA certificate
                bytes32 hash = sha256(
                    abi.encodePacked(fatherCert.tbsCertificate, fatherCert.publicKey.pubKey, fatherCert.signature)
                );
                if (isCACertificate[hash]) {
                    containsTrustedCACertificate = true;
                    break;
                }
            }

            if (!containsTrustedCACertificate) {
                return (false, "untrusted certificate chain");
            }
        }

        return (true, "");
    }
}
