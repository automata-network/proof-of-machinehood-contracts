// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {
    POMEntrypoint,
    NativeAttestPlatform,
    WebAuthNAttestPlatform,
    AttestationStatus,
    WebAuthNAttestationSchema,
    NativeAttestationSchema
} from "../POMEntrypoint.sol";

import {BytesUtils} from "../utils/BytesUtils.sol";

import {LibBitmap} from "solady/utils/LibBitmap.sol";

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

using LibBitmap for LibBitmap.Bitmap;

contract AutomataPOMEntrypoint is POMEntrypoint, AccessControlUpgradeable {
    using BytesUtils for bytes;
    using LibBitmap for LibBitmap.Bitmap;

    // bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant RELAYER_ROLE = 0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;

    mapping(WebAuthNAttestPlatform => address) _webAuthNVerifiers;
    mapping(NativeAttestPlatform => address) _nativeAttestVerifiers;

    /// @dev bitmap is used to keep track of attestation data collision
    /// this prevents attackers from re-submitting attested data
    LibBitmap.Bitmap internal proofBitmap;

    mapping(bytes32 paddedWalletAddress => bytes attData) webAuthNAttData;
    /// @notice the attestation id is the keccak256 hash of the device identity
    mapping(bytes32 attestationId => bytes attData) nativeAttData;

    mapping(bytes32 deviceIdHash => uint256 nullifierHash) public world_deviceBinding;
    mapping(uint256 nullifierHash => bytes32 deviceIdHash) public world_nullifierHashes;
    // TBD mapping(uint256 nullifierHash => bytes ???) public world_extraInfo;

    event WebAuthNAttested(WebAuthNAttestPlatform indexed platform, address indexed walletAddress);
    event NativeAttested(NativeAttestPlatform indexed platform, bytes deviceIdentity);

    // a7e31dec
    error Duplicate_Attestation_Found();

    constructor() {
        _disableInitializers();
    }

    function initialize(address _admin) external reinitializer(2) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    function setWebAuthNVerifier(WebAuthNAttestPlatform platform, address verifier)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        _webAuthNVerifiers[platform] = verifier;
    }

    function setNativeAttVerifier(NativeAttestPlatform platform, address verifier)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        _nativeAttestVerifiers[platform] = verifier;
    }

    function webAuthNAttestationSchemaId() public pure override returns (bytes32) {
        return bytes32(0);
    }

    function nativeAttestationSchemaId() public pure override returns (bytes32) {
        return bytes32(0);
    }

    function getWebAuthNAttestationStatus(bytes32 walletAddress)
        external
        view
        override
        returns (AttestationStatus status, bytes memory att)
    {
        att = webAuthNAttData[walletAddress];
        if (att.length > 0) {
            status = AttestationStatus.REGISTERED;
        }
    }

    function getNativeAttestationStatus(bytes calldata deviceIdentity)
        external
        view
        override
        returns (AttestationStatus status, bytes memory att)
    {
        att = nativeAttData[keccak256(deviceIdentity)];

        if (att.length > 0) {
            NativeAttestationSchema memory nativeAttestation = abi.decode(att, (NativeAttestationSchema));
            if (block.timestamp > nativeAttestation.expiry) {
                status = AttestationStatus.EXPIRED;
            } else {
                status = AttestationStatus.REGISTERED;
            }
        }
    }

    function _attestWebAuthn(WebAuthNAttestationSchema memory att) internal override returns (bytes32 attestationId) {
        attestationId = att.walletAddress;
        bytes memory data = abi.encode(att);
        _checkDuplicationPayload(att.proofHash);
        webAuthNAttData[attestationId] = data;
        emit WebAuthNAttested(att.platform, address(uint160(uint256(att.walletAddress))));
    }

    function _attestNative(NativeAttestationSchema memory att) internal override returns (bytes32 attestationId) {
        attestationId = keccak256(att.deviceIdentity);
        bytes memory data = abi.encode(att);
        _checkDuplicationPayload(keccak256(data));
        nativeAttData[attestationId] = data;
        emit NativeAttested(att.platform, att.deviceIdentity);
    }

    function platformMapToNativeVerifier(NativeAttestPlatform platform) public view override returns (address) {
        return _nativeAttestVerifiers[platform];
    }

    function platformMapToWebAuthNverifier(WebAuthNAttestPlatform platform) public view override returns (address) {
        return _webAuthNVerifiers[platform];
    }

    /// @dev replay protection
    function _checkDuplicationPayload(bytes32 hash) private {
        uint256 key = uint256(hash);
        if (proofBitmap.get(key)) {
            revert Duplicate_Attestation_Found();
        }
        proofBitmap.set(key);
    }

    function getDeviceFlags(bytes calldata deviceIdentity) public view returns (uint256 flags) {
        bytes32 deviceHash = keccak256(deviceIdentity);
        flags = 0;
        if (world_deviceBinding[deviceHash] != 0) flags |= 1;
    }

    function world_bindDevice(bytes calldata deviceId, uint256 nullifierHash) external onlyRole(RELAYER_ROLE) {
        (AttestationStatus status,) = this.getNativeAttestationStatus(deviceId);
        require(status == AttestationStatus.REGISTERED, "Unregistered device");

        bytes32 oldDevice = world_nullifierHashes[nullifierHash];
        bytes memory att = nativeAttData[oldDevice];
        if (att.length > 0) {
            NativeAttestationSchema memory nativeAttestation = abi.decode(att, (NativeAttestationSchema));
            require(block.timestamp > nativeAttestation.expiry, "Duplicate binding");

            // Clear expired device binding
            world_deviceBinding[oldDevice] = 0;
        }

        bytes32 deviceHash = keccak256(deviceId);
        uint256 oldNullifier = world_deviceBinding[deviceHash];
        if (oldNullifier != 0) {
            // Clear old nullifierHash binding
            world_nullifierHashes[oldNullifier] = 0;
        }

        world_deviceBinding[deviceHash] = nullifierHash;
        world_nullifierHashes[nullifierHash] = deviceHash;
    }

    // TODO: contract verify signature, no need access ctrl
    // function world_unbindDevice(bytes calldata deviceId) external {
    //     bytes32 deviceHash = keccak256(deviceId);
    //     // (AttestationStatus status,) = this.getNativeAttestationStatus(deviceId);
    //     // require(status == AttestationStatus.REGISTERED, "Unregistered device");
    //     uint256 nullifierHash = world_deviceBinding[deviceHash];
    //     world_deviceBinding[deviceHash] = 0;
    //     world_nullifierHashes[nullifierHash] = 0;
    // }

    // Reserved
    // function world_unbindNullifierHash(uint256 nullifierHash) external onlyRole() {
    //     bytes32 deviceHash = world_nullifierHashes[nullifierHash];
    //     world_deviceBinding[deviceHash] = 0;
    //     world_nullifierHashes[nullifierHash] = 0;
    // }
}
