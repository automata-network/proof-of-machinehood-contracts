// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {
    NativeX5CBase, 
    X509Helper, 
    X509CertObj, 
    X509VerificationProofObj, 
    PublicKeyAlgorithm, 
    SignatureAlgorithm
} from "./base/NativeX5CBase.sol";
import {BytesUtils} from "../utils/BytesUtils.sol";
import {Asn1Decode, NodePtr} from "../utils/Asn1Decode.sol";

/// @dev basic configuration to deem a valid attestation
/// as referenced: https://github.com/automata-network/machinehood-rn/blob/e618d5c4440c525eacdd37fef75074c3a7d6a0fc/android/app/src/main/java/com/automata/pomrn/POMVerification.kt#L48-L54
struct BasicAttestationObject {
    uint256 attestationVersion;
    SecurityLevel securityLevel;
    string packageName;
    uint256 packageVersion;
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

    error Invalid_Android_Id();
    error Attestation_Not_Accepted_By_Policy();
    error Certificate_Revoked(uint256 serialNumber);
    error Invalid_Cert_Chain();

    // 1.3.6.1.4.1.11129.2.1.17
    bytes constant ATTESTATION_OID = hex"2B06010401D679020111";
    // 1.3.6.1.4.1.11129.2.1.30
    bytes constant PROVISIONING_INFO_OID = hex"2B06010401D67902011E";
    // https://developer.android.com/privacy-and-security/security-key-attestation#key_attestation_ext_schema
    uint256 constant ATTESTATION_APPLICATION_ID_CONTEXT_TAG = 709;

    constructor(address _sigVerifyLib) NativeX5CBase(_sigVerifyLib) {}

    /// @dev implement getter to determine the revocation status of the given serial number of a certificate
    /// @dev you must implement a method (access-controlled) to store CRLs on chain
    /// Official CRL list can be fetched via https://android.googleapis.com/attestation/status
    function certIsRevoked(uint256 serialNum) public view virtual returns (bool);

    /// @dev implement this method to specify the set of values that you expect the hardware-backed key to contain
    function _validateAttestation(BasicAttestationObject memory att) internal view virtual returns (bool);

    /**
     * @notice built-in method to perform verification on the provided payload
     * @param deviceIdentity unique device identifier
     * @param payload is an array must contain the following in the CORRECT order:
     * - index 0: contains the x5c[] certificate chain, encoded in DER
     * - index 1: the signature that signs over sha256(deviceIdentity) with the attested key
     */
    function _verifyPayload(bytes calldata deviceIdentity, bytes[] calldata payload)
        internal
        view
        override
        returns (bytes memory attestationData, uint256 expiry)
    {
        bytes[] memory x5c = abi.decode(payload[0], (bytes[]));
        X509VerificationProofObj memory x5cProof = abi.decode(payload[1], (X509VerificationProofObj));

        // Step 1: Verify certificate chain
        bool verified = _checkX509Proof(x5cProof);
        if (!verified) {
            revert Invalid_Cert_Chain();
        }

        (X509CertObj memory attestationCert, uint256 attestationPtr, bytes memory attestationExtension) =
           _getAttestationCert(x5c);
        bytes memory attestedPubKey = attestationCert.subjectPublicKey;
        expiry = attestationCert.validityNotAfter;

        // Step 2: validate attestation details from the corresponding certificate
        BasicAttestationObject memory att = _parseAttestationExtension(attestationExtension, attestationPtr);
        bool attValidated = _validateAttestation(att);
        if (!attValidated) {
            revert Attestation_Not_Accepted_By_Policy();
        }

        // Step 3: validate Android_ID
        bool sigVerified = _verifyAndroidId(deviceIdentity, payload[1], attestedPubKey);
        if (!sigVerified) {
            revert Invalid_Android_Id();
        }

        attestationData = attestedPubKey;
    }

    function _verifyAndroidId(bytes calldata deviceIdentity, bytes memory signature, bytes memory attestedPubKey)
        private
        view
        returns (bool verified)
    {
        verified = sigVerifyLib.verifyES256Signature(deviceIdentity, signature, attestedPubKey);
    }

    /// @dev we cannot assume that the key attestation certificate extension is in the leaf certificate
    /// @dev instead, we should only trust the one that is closest to the root
    /// See https://developer.android.com/privacy-and-security/security-key-attestation#verifying for more info
    function _getAttestationCert(bytes[] memory x5c)
        internal
        view
        returns (X509CertObj memory attestationCert, uint256 attestationPtr, bytes memory attestationExtension)
    {
        // Step 1: check if the root contains the trusted key
        (PublicKeyAlgorithm issuerKeyAlgo, bytes memory issuerKey) = X509Helper.getSubjectPublicKeyInfo(x5c[0]);
        (bytes memory tbs,, bytes memory sig) = X509Helper.getTbsAndSigInfo(x5c[0]);
        bytes32 rootHash = sha256(abi.encodePacked(tbs, issuerKey, sig));
        bool provisiongFound;
        bool attestationFound;
        if (isCACertificate[rootHash]) {
            for (uint256 i = x5c.length - 1; i > 0; i--) {
                X509CertObj memory currentSubject = X509Helper.parseX509DER(x5c[i - 1]);

                // check crl
                bool revoked = certIsRevoked(currentSubject.serialNumber);
                if (revoked) {
                    revert Certificate_Revoked(currentSubject.serialNumber);
                }

                // // determine validity
                // if (
                //     block.timestamp < currentSubject.validityNotBefore
                //         || block.timestamp > currentSubject.validityNotAfter
                // ) {
                //     revert("expired certificate found");
                // }

                // bool sigVerified = _verifyCertSig(
                //     issuerKeyAlgo, currentSubject.issuerSigAlgo, issuerKey, currentSubject.signature, currentSubject.tbs
                // );

                // require(sigVerified, "Failed to verify cert signature");

                // Check for attestation extension
                (attestationFound, attestationPtr, attestationExtension) =
                    _findOID(x5c[i - 1], currentSubject.extensionPtr, ATTESTATION_OID);
                if (attestationFound) {
                    attestationCert = currentSubject;
                    break;
                } else {
                    if (provisiongFound) {
                        revert("cert does not contain valid attestation");
                    }
                }

                // Check for provisioning extension
                if (!provisiongFound) {
                    (provisiongFound,,) = _findOID(x5c[i - 1], currentSubject.extensionPtr, PROVISIONING_INFO_OID);
                }

                // prepare for next iteration
                issuerKeyAlgo = currentSubject.subjectPublicKeyAlgo;
            }
        }
    }

    function _findOID(bytes memory der, uint256 extensionPtr, bytes memory oid)
        private
        pure
        returns (bool oidFound, uint256 retPtr, bytes memory retDer)
    {
        if (der[extensionPtr.ixs()] != 0xA3) {
            revert("Ptr does not point to a valid extension");
        }

        uint256 parentPtr = der.firstChildOf(extensionPtr);
        uint256 ptr = der.firstChildOf(parentPtr);

        while (ptr != 0) {
            uint256 internalPtr = der.firstChildOf(ptr);
            // check OID
            if (der[internalPtr.ixs()] == 0x06) {
                oidFound = der.bytesAt(internalPtr).equals(oid);
                if (oidFound) {
                    internalPtr = der.nextSiblingOf(internalPtr);
                    retDer = der.bytesAt(internalPtr);
                    retPtr = retDer.root();
                }
            }
            if (ptr.ixl() < parentPtr.ixl()) {
                ptr = der.nextSiblingOf(ptr);
            } else {
                ptr = 0; // equivalent to break
            }
        }
    }

    function _parseAttestationExtension(bytes memory attestationDer, uint256 attestationPtr)
        private
        pure
        returns (BasicAttestationObject memory att)
    {
        // attestationVersion is the 1st element
        attestationPtr = attestationDer.firstChildOf(attestationPtr);
        att.attestationVersion = attestationDer.uintAt(attestationPtr);

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
        (bytes memory packageNameBytes, bytes memory packageSignature, uint256 packageVersion) =
            _parseSoftwareEnforcedBytes(softwareEnforcedBytes);

        att.packageName = string(packageNameBytes);
        att.packageSignature = packageSignature;
        att.packageVersion = packageVersion;
        att.fullAttestationDer = attestationDer;
    }

    function _parseSoftwareEnforcedBytes(bytes memory softwareEnforcedBytes)
        private
        pure
        returns (bytes memory packageNameBytes, bytes memory packageSignature, uint256 packageVersion)
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
        packageVersion = ret.uintAt(ret.nextSiblingOf(namePtr));
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
