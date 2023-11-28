// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "./AttestationVerificationBase.sol";

contract Yubikey is AttestationVerificationBase {
    struct AttStmt {
        ISigVerifyLib.Algorithm alg;
        bytes signature;
        // Certificate chain
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

        // Step 1: Verify attestation statement signature
        {
            // Concatenate authData and clientDataHash
            bytes32 clientDataHash = sha256(bytes(clientData));
            bytes memory message = abi.encodePacked(authData, clientDataHash);

            bool validSig =
                sigVerify.verifyAttStmtSignature(message, decoded.signature, decoded.x5c[0].publicKey, decoded.alg);
            if (!validSig) {
                return (false, "invalid sig");
            }
        }

        // Step 2: Verify the certificate chain
        {
            bool containsTrustedCACertificate = false;
            for (uint256 i = 0; i < decoded.x5c.length - 1; i++) {
                ISigVerifyLib.Certificate memory cert = decoded.x5c[i];
                ISigVerifyLib.Certificate memory fatherCert = decoded.x5c[i + 1];

                // Get the validity and altSubjectName of the certificate
                (uint256 notBefore, uint256 notAfter,) =
                    derParser.parseValidityAndAltSubjectName(cert.tbsCertificate, false);

                // Verify validity of the certificate
                if (notBefore > block.timestamp || notAfter < block.timestamp) {
                    return (false, "expired certificate");
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
