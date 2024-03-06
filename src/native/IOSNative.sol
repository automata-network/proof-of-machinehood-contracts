// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {NativeX5CBase, P256, X509CertObj} from "./base/NativeX5CBase.sol";
import {BytesUtils} from "../utils/BytesUtils.sol";
import {Asn1Decode, NodePtr} from "../utils/Asn1Decode.sol";

struct IOSPayload {
    bytes[] x5c;
    // https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk
    bytes receipt;
    bytes authData;
    bytes32 clientDataHash;
}

struct IOSAssertionPayload {
    bytes signature;
    bytes authData;
}

abstract contract IOSNative is NativeX5CBase {
    using BytesUtils for bytes;
    using Asn1Decode for bytes;
    using NodePtr for uint256;

    // 1.2.840.113635.100.8.2
    bytes constant NONCE_OID = hex"2A864886F763640802";

    error Invalid_App_Id_Hash(bytes32 appIdHashFound);
    error Invalid_Count();
    error Invalid_AAGUID(bytes16 aaguid);
    error Nonce_Mismatch();
    error Mismatch_Key_Identifier(bytes32 keyId);
    error Invalid_Cert_Chain();
    error Invalid_UUID();

    /// @dev configure valid hash of iOS App ID that generates the keypair
    function appIdHash() public view virtual returns (bytes32);

    /// @dev configure the validity of the operating environment
    /// either "appattestdevelop" or "appattest" followed by 7 0x00 bytes
    /// the default behavior accepts both envrionments
    function _aaguidIsValid(bytes16 aaguid) internal view virtual returns (bool);

    /// @dev the payload is the abi encoded of the (CBOR decoded) Payload Object
    function _verifyPayload(bytes calldata deviceIdentity, bytes[] calldata payload)
        internal
        view
        override
        returns (bytes memory attestationData)
    {
        IOSPayload memory payloadObj = abi.decode(payload[0], (IOSPayload));
        IOSAssertionPayload memory assertionObj = abi.decode(payload[1], (IOSAssertionPayload));

        // TODO: verify challenge -> replay protection

        // Step 1: Validate auth data
        // Do we need to return flags here?
        (bytes32 rpid,, uint32 counter, bytes memory credData) = _parseAuthData(payloadObj.authData);
        (bytes16 aaguid, bytes memory credentialId) = _parseCredData(credData);
        if (rpid != appIdHash()) {
            revert Invalid_App_Id_Hash(rpid);
        }
        if (counter > 0) {
            revert Invalid_Count();
        }
        if (!_aaguidIsValid(aaguid)) {
            revert Invalid_AAGUID(aaguid);
        }
        bytes32 expectedNonce = sha256(abi.encodePacked(payloadObj.authData, payloadObj.clientDataHash));

        // Step 2: Verify x5c chain, keyId and nonce
        (bool verified, uint256 extensionPtr, bytes memory attestedPubkey) = _verifyCertChain(payloadObj.x5c);
        if (!verified) {
            revert Invalid_Cert_Chain();
        }
        bytes32 nonce = _extractNonceFromCredCert(payloadObj.x5c[0], extensionPtr);
        if (expectedNonce != nonce) {
            revert Nonce_Mismatch();
        }
        bytes32 keyIdFound = sha256(attestedPubkey);
        if (keyIdFound != sha256(credentialId)) {
            revert Mismatch_Key_Identifier(keyIdFound);
        }

        // Step 3: Verify Device UUID
        bool uuidVerified = _verifyUUID(deviceIdentity, attestedPubkey, assertionObj.signature, assertionObj.authData);
        if (!uuidVerified) {
            revert Invalid_UUID();
        }
        attestationData = abi.encode(attestedPubkey, payloadObj.receipt);
    }

    function _parseAuthData(bytes memory authData)
        private
        pure
        returns (bytes32 rpid, bytes1 flag, uint32 counter, bytes memory credData)
    {
        rpid = bytes32(authData.substring(0, 32));
        flag = bytes1(authData.substring(32, 1));
        counter = uint32(bytes4(authData.substring(33, 4)));

        uint256 n = authData.length - 37;
        if (n > 0) {
            credData = authData.substring(37, n);
        }
    }

    function _parseCredData(bytes memory credData) private pure returns (bytes16 aaguid, bytes memory credentialId) {
        aaguid = bytes16(credData.substring(37, 16));
        uint16 credIdLen = uint16(bytes2(credData.substring(53, 2)));
        credentialId = credData.substring(55, credIdLen);
    }

    function _verifyCertChain(bytes[] memory x5c)
        internal
        view
        returns (bool verified, uint256 extensionPtr, bytes memory attestedPubkey)
    {
        for (uint256 i = 0; i < x5c.length - 1; i++) {
            // check whether the certificate has expired
            bool certIsValid = x509Helper.certIsNotExpired(x5c[i]);
            if (!certIsValid) {
                return (false, 0, hex"");
            }

            // check whether the certificate is signed by a valid and trusted issuer
            X509CertObj memory cert = x509Helper.parseX509DER(x5c[i]);
            bytes memory issuerPubKey = x509Helper.getSubjectPublicKey(x5c[i + 1]);

            // TODO: this assumption is incorrect, because aside from credcert
            // all other cert uses the P384SHA signature algorithm
            // bool sigVerified = P256.verifySignatureAllowMalleability(
            //     sha256(cert.tbs),
            //     uint256(bytes32(cert.signature.substring(0, 32))),
            //     uint256(bytes32(cert.signature.substring(32, 32))),
            //     uint256(bytes32(issuerPubKey.substring(0, 32))),
            //     uint256(bytes32(issuerPubKey.substring(32, 32)))
            // );
            // if (!sigVerified) {
            //     return (false, 0, hex"");
            // }

            // credCert is the leaf
            if (i == 0) {
                extensionPtr = cert.extensionPtr;
                attestedPubkey = cert.subjectPublicKey;
            }

            // check whether the issuer is trusted. If so, break the loop
            (bytes memory issuerTbs, bytes memory issuerSig) = x509Helper.getTbsAndSig(x5c[i + 1]);
            bytes32 issuerHash = sha256(abi.encodePacked(issuerTbs, issuerPubKey, issuerSig));
            if (isCACertificate[issuerHash]) {
                verified = true;
                break;
            }
        }
    }

    function _extractNonceFromCredCert(bytes memory credCert, uint256 extensionPtr)
        private
        pure
        returns (bytes32 nonce)
    {
        if (credCert[extensionPtr.ixs()] != 0xA3) {
            revert("Ptr does not point to a valid extension");
        }

        uint256 parentPtr = credCert.firstChildOf(extensionPtr);
        uint256 ptr = credCert.firstChildOf(parentPtr);

        // begin iterating through the extensions until we find the nonce OID
        while (ptr != 0) {
            uint256 internalPtr = credCert.firstChildOf(ptr);

            // check OID
            if (credCert[internalPtr.ixs()] == 0x06) {
                if (credCert.bytesAt(internalPtr).equals(NONCE_OID)) {
                    // Nonce found
                    internalPtr = credCert.nextSiblingOf(internalPtr);
                    internalPtr = credCert.firstChildOf(internalPtr);
                    nonce = bytes32(credCert.bytesAt(internalPtr));
                    break;
                }
            }

            if (ptr.ixl() <= parentPtr.ixl()) {
                ptr = credCert.nextSiblingOf(ptr);
            } else {
                ptr = 0; // equivalent to break
            }
        }
    }

    function _verifyUUID(
        bytes calldata deviceIdentity,
        bytes memory attestedPubKey,
        bytes memory signature,
        bytes memory authData
    ) private view returns (bool verified) {
        // auth data verification
        (bytes32 rpid,, uint32 counter,) = _parseAuthData(authData);
        if (rpid != appIdHash()) {
            return false;
        }
        if (counter == 0) {
            // pubkey not attested
            return false;
        }

        // sig verification
        bytes32 deviceHash = sha256(deviceIdentity);
        bytes memory message = abi.encodePacked(authData, deviceHash);
        bytes32 digest = sha256(message);
        verified = P256.verifySignatureAllowMalleability(
            digest,
            uint256(bytes32(signature.substring(0, 32))),
            uint256(bytes32(signature.substring(32, 32))),
            uint256(bytes32(attestedPubKey.substring(0, 32))),
            uint256(bytes32(attestedPubKey.substring(32, 32)))
        );
    }
}
