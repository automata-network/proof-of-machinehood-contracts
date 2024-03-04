// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "../utils/SHA1.sol";
import "../utils/CertInfoParser.sol";
import "./AttestationVerificationBase.sol";

contract WindowsTPM is AttestationVerificationBase {
    struct AttStmt {
        ISigVerifyLib.Algorithm alg;
        bytes sig;
        ISigVerifyLib.Certificate[] x5c;
        bytes certInfo;
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

        // Verify hash
        {
            bytes32 clientDataHash = sha256(bytes(clientData));
            bytes20 expectedExtraData = SHA1.sha1(abi.encodePacked(authData, clientDataHash));
            bytes20 extraData = CertInfoParser.parseExtraData(decoded.certInfo);
            // Verify certInfo's extraData equals to the hash of attToBeSigned
            if (extraData != expectedExtraData) {
                return (false, "invalid extra data");
            }
        }

        // Verify the signature
        bool validSig =
            sigVerify.verifyAttStmtSignature(decoded.certInfo, decoded.sig, decoded.x5c[0].publicKey, decoded.alg);
        if (!validSig) {
            return (false, "invalid sig");
        }

        // Verify the certificate chain
        {
            bool containsTrustedCACertificate = false;
            for (uint256 i = 0; i < decoded.x5c.length - 1; i++) {
                ISigVerifyLib.Certificate memory cert = decoded.x5c[i];
                ISigVerifyLib.Certificate memory fatherCert = decoded.x5c[i + 1];

                (uint256 notBefore, uint256 notAfter,) =
                    derParser.parseValidityAndAltSubjectName(cert.tbsCertificate, false);

                // Verify validity of the certificate
                if (notBefore > block.timestamp || notAfter < block.timestamp) {
                    return (false, "invalid sig");
                }

                // Verify the signature of the certificate
                bool validCertSig = sigVerify.verifyCertificateSignature(
                    cert.tbsCertificate, cert.signature, fatherCert.publicKey, cert.sigAlg
                );
                if (!validCertSig) {
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
