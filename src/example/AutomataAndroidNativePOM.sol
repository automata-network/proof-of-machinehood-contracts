// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {AndroidNative, BasicAttestationObject, SecurityLevel} from "../native/AndroidNative.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {X509ChainVerifier} from "@automata-network/risc0-zk-x509/X509ChainVerifier.sol";

contract AutomataAndroidNativePOM is AndroidNative, Ownable {

    /// @notice the root public key is the keccak256 hash of abi-encoded tuple consists of (e, n) of the RSA public key
    /// https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
    bytes32 constant ANDROID_ROOT_CERTIFICATE_PUBLIC_KEY_HASH = 0x44a4f06250b05b1c9b1d2a74cb8a525ef2a45ae36baf767c9ce0ae7f38889fb0;
    
    string public packageName;

    mapping(uint256 => bool) _serialNumRevoked;
    mapping(bytes32 => bool) _trustedCAs;
    mapping(address => bool) _teeTrusted;

    // Configuration on attestation attributes that this contract deems valid
    mapping(uint256 => bool) _attestationVersionsAllowed;
    mapping(uint256 => bool) _packageVersionsAllowed;
    mapping(bytes32 => bool) _packageSignaturesAllowed;

    constructor(address _sigVerifyLib, address _x509Verifier) AndroidNative(_sigVerifyLib, _x509Verifier) {
        _initializeOwner(msg.sender);
        packageName = "com.automata.pomrn";
    }

    function addCACert(bytes32 hash) external override onlyOwner {
        _trustedCAs[hash] = true;
    }

    function removeCACert(bytes32 hash) external override onlyOwner {
        _trustedCAs[hash] = false;
    }

    function caIsTrusted(bytes32 hash) public view override returns (bool) {
        return _trustedCAs[hash];
    }

    function setTrustedTee(address tee, bool trusted) external override onlyOwner {
        _teeTrusted[tee] = trusted;
    }

    function updateX509Verifier(address _x509Verifier) public override onlyOwner {
        x509Verifier = X509ChainVerifier(_x509Verifier);
    }

    function teeIsTrusted(address tee) public view override returns (bool) {
        return _teeTrusted[tee];
    }

    function revokeCertBatch(uint256[] calldata serialNums) external onlyOwner {
        for (uint256 i = 0; i < serialNums.length; i++) {
            if (!_serialNumRevoked[serialNums[i]]) {
                _revokeCert(serialNums[i], true);
            }
        }
    }

    function setSingleCertRevocationStatus(uint256 serialNum, bool revoked) external onlyOwner {
        _revokeCert(serialNum, revoked);
    }

    function setPackageName(string calldata _packageName) external onlyOwner {
        packageName = _packageName;
    }

    
    function checkRootPublicKey(bytes memory rootPublicKey) public pure override returns (bool) {
        return keccak256(rootPublicKey) == ANDROID_ROOT_CERTIFICATE_PUBLIC_KEY_HASH;
    }

    /// @dev essentially configures which KeyMaster version that the contract allows
    /// https://developer.android.com/privacy-and-security/security-key-attestation#key_attestation_ext_schema_keydescription
    function setSupportedAttestationVersions(uint256 attVersion, bool supported) external onlyOwner {
        _attestationVersionsAllowed[attVersion] = supported;
    }

    /// https://developer.android.com/privacy-and-security/security-key-attestation#key_attestation_ext_schema_attestationid
    function setSupportedPackageVersions(uint256 packageVersion, bool supported) external onlyOwner {
        _packageVersionsAllowed[packageVersion] = supported;
    }

    /// https://developer.android.com/privacy-and-security/security-key-attestation#key_attestation_ext_schema_attestationid
    function setSupportedPackageSignature(bytes calldata packageSignature, bool supported) external onlyOwner {
        bytes32 sigHash = keccak256(packageSignature);
        _packageSignaturesAllowed[sigHash] = supported;
    }

    function certIsRevoked(uint256 serialNum) public view override returns (bool) {
        return _serialNumRevoked[serialNum];
    }

    function _validateAttestation(BasicAttestationObject memory att) internal view override returns (bool) {
        return _attestationVersionsAllowed[att.attestationVersion]
            || _packageSignaturesAllowed[keccak256(att.packageSignature)] || _packageVersionsAllowed[att.packageVersion]
            || _securityLevelAllowed(att.securityLevel);
    }

    function _revokeCert(uint256 serialNum, bool revoked) private {
        _serialNumRevoked[serialNum] = revoked;
    }

    /// @dev cannot trust SecurityLevel == Software
    /// @notice https://developer.android.com/privacy-and-security/security-key-attestation#key_attestation_ext_schema_securitylevel
    function _securityLevelAllowed(SecurityLevel attSecurityLevel) private pure returns (bool allowed) {
        allowed = attSecurityLevel == SecurityLevel.TrustedEnvironment || attSecurityLevel == SecurityLevel.StrongBox;
    }
}
