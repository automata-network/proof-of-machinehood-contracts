// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {NativeX5CBase, X509CertObj, P256} from "./base/NativeX5CBase.sol";
import {BytesUtils} from "../utils/BytesUtils.sol";
import {Asn1Decode, NodePtr} from "../utils/Asn1Decode.sol";

struct AndroidPayload {
    bytes[] x5c;
    bytes signature;
}

struct BasicAttestationObject {
    SecurityLevel securityLevel;
    string packageName;
    bytes packageSignature;
    // this can be parsed further by implementation contracts
    // that may require other values that are not in the scope
    // of this attestation object
    bytes fullAttestationDer;
}

// https://source.android.com/docs/security/features/keystore/attestation#securitylevel-values
enum SecurityLevel {
    Software,
    TrustedEnvironment,
    StrongBox
}

// https://source.android.com/docs/security/features/keystore/attestation#verifiedbootstate-values
enum VerifiedBootState {
    Verified,
    SelfSigned,
    Unverified,
    Failed
}

// https://source.android.com/docs/security/features/keystore/attestation#rootoftrust-fields
struct RootOfTrust {
    string verifiedBootKey;
    bool deviceLocked;
    VerifiedBootState verifiedBootState;
    bytes32 verifiedBootHash;
}

abstract contract AndroidNative is NativeX5CBase {
    using Asn1Decode for bytes;
    using NodePtr for uint256;
    using BytesUtils for bytes;

    error Invalid_App_Id(bytes32 appIdFound);
    error Invalid_Cert_Chain();
    error Invalid_Android_Id();
    error Attestation_Not_Accepted_By_Policy();

    // 1.3.6.1.4.1.11129.2.1.17
    bytes constant ATTESTATION_OID = hex"2B06010401D679020111";
    // https://developer.android.com/privacy-and-security/security-key-attestation#key_attestation_ext_schema
    uint256 constant ATTESTATION_APPLICATION_ID_CONTEXT_TAG = 709;

    /// @dev implement this method to specify the set of values that you expect the hardware-backed key to contain
    function _validateAttestation(BasicAttestationObject memory att) internal view virtual returns (bool);

    function _verifyPayload(bytes calldata deviceIdentity, bytes[] calldata payload)
        internal
        view
        override
        returns (bytes memory attestationData)
    {
        AndroidPayload memory payloadObj = abi.decode(payload[0], (AndroidPayload));

        // Step 1: Verify certificate chain
        (bool certChainVerified, uint256 attestationCertIndex, bytes memory attestedPubKey) =
            _verifyCertChain(payloadObj.x5c);
        if (!certChainVerified) {
            revert Invalid_Cert_Chain();
        }

        // Step 2: validate Android_ID
        bool sigVerified = _verifyAndroidId(deviceIdentity, payloadObj.signature, attestedPubKey);
        if (!sigVerified) {
            revert Invalid_Android_Id();
        }

        // Step 3: validate attestation details from the corresponding certificate
        BasicAttestationObject memory att = _parseAttestationCert(payloadObj.x5c[attestationCertIndex]);
        bool attValidated = _validateAttestation(att);
        if (!attValidated) {
            revert Attestation_Not_Accepted_By_Policy();
        }

        attestationData = attestedPubKey;
    }

    function _verifyAndroidId(bytes calldata deviceIdentity, bytes memory signature, bytes memory attestedPubKey)
        private
        view
        returns (bool verified)
    {
        bytes32 deviceHash = sha256(deviceIdentity);
        verified = P256.verifySignatureAllowMalleability(
            deviceHash,
            uint256(bytes32(signature.substring(0, 32))),
            uint256(bytes32(signature.substring(32, 32))),
            uint256(bytes32(attestedPubKey.substring(0, 32))),
            uint256(bytes32(attestedPubKey.substring(32, 32)))
        );
    }

    /// @dev we cannot assume that the key attestation certificate extension is in the leaf certificate
    /// See https://developer.android.com/privacy-and-security/security-key-attestation#verifying for more info
    function _verifyCertChain(bytes[] memory x5c)
        internal
        view
        returns (bool verified, uint256 attestationCertIndex, bytes memory attestedPubkey)
    {
        // TODO
        // Signature check
        // CRL check
    }

    function _parseAttestationCert(bytes memory attestationCert)
        private
        view
        returns (BasicAttestationObject memory att)
    {
        X509CertObj memory parsed = x509Helper.parseX509DER(attestationCert);
        uint256 extensionPtr = parsed.extensionPtr;

        if (attestationCert[extensionPtr.ixs()] != 0xA3) {
            revert("Ptr does not point to a valid extension");
        }

        uint256 parentPtr = attestationCert.firstChildOf(extensionPtr);
        uint256 ptr = attestationCert.firstChildOf(parentPtr);

        while (ptr != 0) {
            uint256 internalPtr = attestationCert.firstChildOf(ptr);
            // check OID
            if (attestationCert[internalPtr.ixs()] == 0x06) {
                if (attestationCert.bytesAt(internalPtr).equals(ATTESTATION_OID)) {
                    internalPtr = attestationCert.nextSiblingOf(internalPtr);
                    bytes memory attestationDer = attestationCert.bytesAt(internalPtr);

                    uint256 attestationPtr = attestationDer.root();
                    attestationPtr = attestationDer.firstChildOf(attestationPtr);

                    // attestationSecurityLevel is the 2nd element of the KeyDescription sequence
                    attestationPtr = attestationDer.nextSiblingOf(attestationPtr);
                    att.securityLevel = SecurityLevel(uint8(bytes1(attestationDer.bytesAt(attestationPtr))));

                    // attestationApplicationId is tagged with [709] in the softwareEnforced sequence
                    // which is the 7th element of the KeyDescription sequence
                    attestationPtr = attestationDer.nextSiblingOf(attestationPtr);
                    attestationPtr = attestationDer.nextSiblingOf(attestationPtr);
                    attestationPtr = attestationDer.nextSiblingOf(attestationPtr);
                    attestationPtr = attestationDer.nextSiblingOf(attestationPtr);
                    attestationPtr = attestationDer.nextSiblingOf(attestationPtr);

                    bytes memory softwareEnforcedBytes = attestationDer.bytesAt(attestationPtr);
                    (bytes memory packageNameBytes, bytes memory packageSignature) =
                        _parseSoftwareEnforcedBytes(softwareEnforcedBytes);

                    att.packageName = string(packageNameBytes);
                    att.packageSignature = packageSignature;
                    att.fullAttestationDer = attestationDer;
                }
            }

            if (ptr.ixl() < parentPtr.ixl()) {
                ptr = attestationCert.nextSiblingOf(ptr);
            } else {
                ptr = 0; // equivalent to break
            }
        }
    }

    function _parseSoftwareEnforcedBytes(bytes memory softwareEnforcedBytes)
        private
        pure
        returns (bytes memory packageNameBytes, bytes memory packageSignature)
    {
        uint256 offset;
        uint256 context;
        bytes memory der = softwareEnforcedBytes;
        uint256 beginningPos = 0;
        bytes memory ret;
        bool applicationIdFound;
        while (!applicationIdFound && beginningPos < softwareEnforcedBytes.length) {
            (offset, context) = _getContextNumberFromTag(der);
            applicationIdFound = context == ATTESTATION_APPLICATION_ID_CONTEXT_TAG;
            uint256 ptr = _readNodeLength(softwareEnforcedBytes, beginningPos + offset, offset + 1);
            if (applicationIdFound) {
                ret = softwareEnforcedBytes.bytesAt(ptr);
            } else {
                beginningPos = ptr.ixl() + 1;
                der = softwareEnforcedBytes.substring(beginningPos, der.length - beginningPos);
            }
        }

        require(applicationIdFound, "missing attestation app id");

        // get the sequence from the octet string
        uint256 retPtr = ret.root();
        ret = ret.bytesAt(retPtr);
        uint256 namePtr = ret.firstChildOf(retPtr);
        uint256 sigPtr = ret.nextSiblingOf(namePtr);

        namePtr = ret.firstChildOf(namePtr);
        namePtr = ret.firstChildOf(namePtr);
        sigPtr = ret.firstChildOf(sigPtr);

        packageNameBytes = ret.bytesAt(namePtr);
        packageSignature = ret.bytesAt(sigPtr);
    }

    /// @dev if a tag belongs to the context-specific class (8th bit = 1, 7th bit = 0)
    /// that means a content is being tagged with a number in square brackets, [N]
    /// if N > 30 (11110), the tag is encoded in long form
    /// @return offset - the position of the last tag byte
    /// @return context - the context number that the content is tagged with
    function _getContextNumberFromTag(bytes memory der) private pure returns (uint256 offset, uint256 context) {
        bool isContextSpecific = der[0] & 0x80 == 0x80;
        require(isContextSpecific, "provided DER does not have a context-specific tag");
        bytes1 val = der[0] & 0x1f;
        bool tagIsLong = val == 0x1f;
        if (tagIsLong) {
            offset = 1;
            bool stop = der[offset] & 0x80 == 0x00;
            while (!stop) {
                context += uint8(bytes1(der[offset] & 0x7f));
                context <<= 7;
                stop = der[++offset] & 0x80 == 0x00;
            }
            context += uint8(bytes1(der[offset] & 0x7f));
        } else {
            context = uint8(val);
        }
    }

    /// Modified from Asn1Decode.sol to accommodate long-form tags
    /// @param ix refers to the index of the last tag byte
    function _readNodeLength(bytes memory der, uint256 ix, uint256 tagSize) private pure returns (uint256) {
        uint256 length;
        uint80 ixFirstContentByte;
        uint80 ixLastContentByte;
        if ((der[ix + 1] & 0x80) == 0) {
            length = uint8(der[ix + 1]);
            ixFirstContentByte = uint80(ix + 2);
            ixLastContentByte = uint80(ixFirstContentByte + length - 1);
        } else {
            uint8 lengthbytesLength = uint8(der[ix + 1] & 0x7F);
            if (lengthbytesLength == 1) {
                length = der.readUint8(ix + 2);
            } else if (lengthbytesLength == 2) {
                length = der.readUint16(ix + 2);
            } else {
                length = uint256(der.readBytesN(ix + 2, lengthbytesLength) >> (32 - lengthbytesLength) * 8);
            }
            ixFirstContentByte = uint80(ix + 2 + lengthbytesLength);
            ixLastContentByte = uint80(ixFirstContentByte + length - 1);
        }
        return NodePtr.getPtr(ix + 1 - tagSize, ixFirstContentByte, ixLastContentByte);
    }
}
