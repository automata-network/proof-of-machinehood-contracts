// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {NativeX5CBase} from "./base/NativeX5CBase.sol";

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
    error Invalid_App_Id(bytes32 appIdFound);
    error Unacceptable_Security_Level(SecurityLevel securityLevel);
    error Invalid_Root_Of_Trust();
    error Invalid_Cert_Chain();
    error Invalid_Android_Id();

    /// @dev configure valid Android App ID that generates the keypair
    function appId() public view virtual returns (bytes32);

    function acceptableSecurityLevel(SecurityLevel securityLevel) public view virtual returns (bool);

    function checkRootOfTrust(RootOfTrust memory rootOfTrust) public view virtual returns (bool);

    function _verifyPayload(string calldata deviceIdentity, bytes calldata payload)
        internal
        view
        override
        returns (bytes memory attestationData)
    {
        AndroidPayload memory payloadObj = abi.decode(payload, (AndroidPayload));
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
        pure
        returns (bytes32 attestationApplicationId, SecurityLevel securityLevel, RootOfTrust memory rootOfTrust)
    {
        // TODO
    }

    function _verifyAndroidId(string calldata deviceIdentity, bytes memory signature, bytes memory attestedPubKey)
        private
        pure
        returns (bool verified)
    {
        // TODO: verify signature on android id
        // SHA256 vs keccak256 digest??
        // secp256k1 vs secp256r1 (most likely it's going to be secp256r1)
    }
}
