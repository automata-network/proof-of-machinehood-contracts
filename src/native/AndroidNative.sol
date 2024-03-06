// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {NativeX5CBase, X509CertObj} from "./base/NativeX5CBase.sol";
import {BytesUtils} from "../utils/BytesUtils.sol";
import {Asn1Decode, NodePtr} from "../utils/Asn1Decode.sol";

struct AndroidPayload {
    bytes[] x5c;
    bytes signature;
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
    error Unacceptable_Security_Level(SecurityLevel securityLevel);
    error Invalid_Root_Of_Trust();
    error Invalid_Cert_Chain();
    error Invalid_Android_Id();

    // 1.3.6.1.4.1.11129.2.1.17
    bytes constant ATTESTATION_OID = hex"2B06010401D679020111";

    /// @dev configure valid Android App ID that generates the keypair
    function appId() public view virtual returns (bytes32);

    function acceptableSecurityLevel(SecurityLevel securityLevel) public view virtual returns (bool);

    function checkRootOfTrust(RootOfTrust memory rootOfTrust) public view virtual returns (bool);

    function _verifyPayload(bytes calldata deviceIdentity, bytes[] calldata payload)
        internal
        view
        override
        returns (bytes memory attestationData)
    {
        AndroidPayload memory payloadObj = abi.decode(payload[0], (AndroidPayload));
        (bool certChainVerified, uint256 attestationCertIndex, bytes memory attestedPubKey) =
            _verifyCertChain(payloadObj.x5c);
        if (!certChainVerified) {
            revert Invalid_Cert_Chain();
        }
        (bytes32 attestationApplicationId, SecurityLevel securityLevel, RootOfTrust memory rootOfTrust) =
            _parseAttestationCert(payloadObj.x5c[attestationCertIndex]);
        if (attestationApplicationId != appId()) {
            revert Invalid_App_Id(attestationApplicationId);
        }
        if (!acceptableSecurityLevel(securityLevel)) {
            revert Unacceptable_Security_Level(securityLevel);
        }
        if (!checkRootOfTrust(rootOfTrust)) {
            revert Invalid_Root_Of_Trust();
        }
        bool sigVerified = _verifyAndroidId(deviceIdentity, payloadObj.signature, attestedPubKey);
        if (!sigVerified) {
            revert Invalid_Android_Id();
        }
        attestationData = attestedPubKey;
    }

    /// @dev we cannot assume that the key attestation certificate extension is in the leaf certificate
    /// See https://developer.android.com/privacy-and-security/security-key-attestation#verifying for more info
    function _verifyCertChain(bytes[] memory x5c)
        internal
        view
        returns (bool verified, uint256 attestationCertIndex, bytes memory attestedPubkey)
    {
        // TODO
    }

    function _parseAttestationCert(bytes memory attestationCert)
        private
        view
        returns (bytes32 attestationApplicationId, SecurityLevel securityLevel, RootOfTrust memory rootOfTrust)
    {
        // TODO
        // OID 1.3.6.1.4.1.11129.2.1.17

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
                    uint256 attestationPtr = attestationCert.firstChildOf(internalPtr);
                    // TODO: Properly define attestation object
                }
            }

            if (ptr.ixl() <= parentPtr.ixl()) {
                ptr = attestationCert.nextSiblingOf(ptr);
            } else {
                ptr = 0; // equivalent to break
            }
        }
    }

    function _verifyAndroidId(bytes calldata deviceIdentity, bytes memory signature, bytes memory attestedPubKey)
        private
        pure
        returns (bool verified)
    {
        // TODO: verify signature on android id
        // SHA256 vs keccak256 digest??
        // secp256k1 vs secp256r1 (most likely it's going to be secp256r1)
    }
}
