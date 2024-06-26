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

import {Ownable} from "solady/auth/Ownable.sol";

contract AutomataPOMEntrypoint is Ownable, POMEntrypoint {
    using BytesUtils for bytes;

    mapping (WebAuthNAttestPlatform => address) _webAuthNVerifiers;
    mapping (NativeAttestPlatform => address) _nativeAttestVerifiers;

    mapping (bytes32 paddedWalletAddress => bytes attData) public webAuthNAttData;
    /// @notice the attestation id is the keccak256 hash of the device identity
    mapping (bytes32 attestationId => bytes attData) public nativeAttData;

    constructor() {
        _initializeOwner(msg.sender);
    }

    function setWebAuthNVerifier(WebAuthNAttestPlatform platform, address verifier) external onlyOwner {
        _webAuthNVerifiers[platform] = verifier;
    }

    function setNativeAttVerifier(NativeAttestPlatform platform, address verifier) external onlyOwner {
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
        returns (bytes32 attestationId, AttestationStatus status)
    {
        attestationId = walletAddress;
        bytes memory data = webAuthNAttData[walletAddress];
        if (data.length > 0) {
            status = AttestationStatus.REGISTERED;
        }
    }

    function getNativeAttestationStatus(bytes calldata deviceIdentity)
        external
        view
        override
        returns (bytes32 attestationId, AttestationStatus status)
    {
        attestationId = keccak256(deviceIdentity);
        bytes memory data = nativeAttData[attestationId];
        
        if (data.length > 0) {
            uint64 expiry = uint64(bytes8(data.substring(data.length - 8, 8)));
            if (block.timestamp > expiry) {
                status = AttestationStatus.EXPIRED;
            } else {
                status = AttestationStatus.REGISTERED;
            }
        }
    }

    function _attestWebAuthn(WebAuthNAttestationSchema memory att) internal override returns (bytes32 attestationId) {
        attestationId = att.walletAddress;
        webAuthNAttData[attestationId] = abi.encodePacked(
            uint8(att.platform),
            att.walletAddress,
            att.proofHash
        );
    }

    function _attestNative(NativeAttestationSchema memory att, uint256 expiry)
        internal
        override
        returns (bytes32 attestationId)
    {
        attestationId = keccak256(att.deviceIdentity);
        nativeAttData[attestationId] = abi.encodePacked(
            uint8(att.platform),
            att.deviceIdentity,
            keccak256(att.attData),
            uint64(expiry)
        );
    }

    function _platformMapToNativeVerifier(NativeAttestPlatform platform)
        internal
        view
        override
        returns (address)
    {
        return _nativeAttestVerifiers[platform];
    }

    function _platformMapToWebAuthNverifier(WebAuthNAttestPlatform platform)
        internal
        view
        override
        returns (address)
    {
        return _webAuthNVerifiers[platform];
    }
}