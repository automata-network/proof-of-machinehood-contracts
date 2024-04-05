// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {
    NativeX5CBase,
    X509Helper,
    X509CertObj,
    Risc0ProofObj,
    PublicKeyAlgorithm,
    SignatureAlgorithm
} from "./base/NativeX5CBase.sol";
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
    error Untrusted_Root();
    error Invalid_UUID();

    constructor(address _sigVerifyLib, address _x509Verifier) NativeX5CBase(_sigVerifyLib, _x509Verifier) {}

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
        returns (bytes memory attestationData, uint256 expiry)
    {
        IOSPayload memory payloadObj = abi.decode(payload[0], (IOSPayload));
        IOSAssertionPayload memory assertionObj = abi.decode(payload[1], (IOSAssertionPayload));
        Risc0ProofObj memory proof = abi.decode(payload[2], (Risc0ProofObj));

        bytes memory attestedPubkey;
        {
            // TODO: verify challenge -> replay protection

            // Step 0: Check whether the root can be trusted
            bytes[] memory x5c = payloadObj.x5c;
            bool trusted = caIsTrusted(sha256(x5c[x5c.length - 1]));
            if (!trusted) {
                revert Untrusted_Root();
            }

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
            X509CertObj memory credCert = X509Helper.parseX509DER(x5c[0]);
            // determine validity
            if (block.timestamp < credCert.validityNotBefore || block.timestamp > credCert.validityNotAfter) {
                revert("credCert expired");
            }

            bool verified = _checkX509Proof(x5c, proof);
            if (!verified) {
                revert Invalid_Cert_Chain();
            }

            attestedPubkey = credCert.subjectPublicKey;
            expiry = credCert.validityNotAfter;
            bytes32 nonce = _extractNonceFromCredCert(x5c[0], credCert.extensionPtr);
            if (expectedNonce != nonce) {
                revert Nonce_Mismatch();
            }
            bytes32 keyIdFound = sha256(attestedPubkey);
            if (keyIdFound != sha256(credentialId)) {
                revert Mismatch_Key_Identifier(keyIdFound);
            }
        }

        // Step 3: Verify Device UUID
        bool uuidVerified =
            _verifyUUID(deviceIdentity, _process(attestedPubkey, 64), assertionObj.signature, assertionObj.authData);
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
        aaguid = bytes16(credData.substring(0, 16));
        uint16 credIdLen = uint16(bytes2(credData.substring(16, 2)));
        require(uint256(credIdLen) == credData.length - 18, "credData length mismatch");
        credentialId = credData.substring(18, credIdLen);
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
                    internalPtr = credCert.rootOfOctetStringAt(internalPtr);
                    internalPtr = credCert.firstChildOf(internalPtr);
                    bytes memory nonceDer = credCert.allBytesAt(internalPtr);
                    (uint256 offset, uint256 context) = _getContextNumberFromTag(nonceDer);
                    uint256 noncePtr = _readNodeLength(nonceDer, offset, offset + 1);
                    if (context == 1) {
                        nonceDer = nonceDer.bytesAt(noncePtr);
                        noncePtr = _readNodeLength(nonceDer, 0, 1);
                        nonce = bytes32(nonceDer.bytesAt(noncePtr));
                    } else {
                        revert("context not found");
                    }
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
        verified = sigVerifyLib.verifyES256Signature(message, signature, attestedPubKey);
    }
}
