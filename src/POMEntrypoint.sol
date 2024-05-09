// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {AttestationVerificationBase} from "./webauthn/AttestationVerificationBase.sol";
import {NativeBase} from "./native/base/NativeBase.sol";

enum NativeAttestPlatform {
    INAVLID,
    ANDROID,
    IOS,
    MACOS,
    WINDOWS
}

enum WebAuthNAttestPlatform {
    INVALID,
    ANDROID,
    WINDOWS,
    YUBIKEY,
    SELFCLAIM // Used exclusively by Apple devices

}

enum AttestationStatus {
    NON_EXISTENT,
    REGISTERED,
    EXPIRED,
    REVOKED
}

struct WebAuthNAttestationSchema {
    bytes32 walletAddress;
    uint8 platform;
    bytes32 proofHash;
}

struct NativeAttestationSchema {
    uint8 platform;
    bytes deviceIdentity;
    bytes attData;
}

abstract contract POMEntrypoint {
    error Missing_Verifier_Or_Platform_Unsupported();

    function nativeAttest(NativeAttestPlatform platform, bytes calldata deviceIdentity, bytes[] calldata payload)
        external
        returns (bytes32 attestationId)
    {
        address verifier = _platformMapToNativeVerifier(platform);
        if (verifier == address(0)) {
            revert Missing_Verifier_Or_Platform_Unsupported();
        }
        (bytes memory attestedData, uint256 expiry) =
            NativeBase(verifier).verifyAndGetAttestationData(deviceIdentity, payload);
        attestationId = _attestNative(
            NativeAttestationSchema({platform: uint8(platform), deviceIdentity: deviceIdentity, attData: attestedData}),
            expiry
        );
    }

    function webAuthNAttest(
        WebAuthNAttestPlatform platform,
        bytes32 walletAddress,
        bytes calldata attStmt,
        bytes calldata authData,
        bytes calldata clientData
    ) external returns (bytes32 attestationId) {
        address verifier = _platformMapToWebAuthNverifier(platform);
        if (verifier == address(0)) {
            revert Missing_Verifier_Or_Platform_Unsupported();
        }
        (bool success, string memory reason) = AttestationVerificationBase(verifier).verifyAttStmt(
            abi.encodePacked(walletAddress), attStmt, authData, clientData
        );
        require(success, reason);
        bytes32 proofHash = keccak256(abi.encodePacked(attStmt, authData, clientData));
        attestationId = _attestWebAuthn(
            WebAuthNAttestationSchema({walletAddress: walletAddress, platform: uint8(platform), proofHash: proofHash})
        );
    }

    function webAuthNAttestationSchemaId() public view virtual returns (bytes32 WEBAUTHN_MACHINEHOOD_SCHEMA_ID);

    function nativeAttestationSchemaId() public view virtual returns (bytes32 NATIVE_MACHINEHOOD_SCHEMA_ID);

    function getNativeAttestationFromDeviceIdentity(NativeAttestPlatform platform, bytes calldata deviceIdentity)
        public
        view
        virtual
        returns (bytes32 attestationId);

    /**
     * @notice Gets the WebAuthN attestation ID and status from the given device identity
     */
    function getWebAuthNAttestationStatus(WebAuthNAttestPlatform platform, address walletAddress)
        external
        view
        virtual
        returns (bytes32 attestationId, AttestationStatus status);

    /**
     * @notice Gets the native attestation ID and status from the given device identity
     */
    function getNativeAttestationStatus(NativeAttestPlatform platform, bytes calldata deviceIdentity)
        external
        view
        virtual
        returns (bytes32 attestationId, AttestationStatus status);

    function _platformMapToNativeVerifier(NativeAttestPlatform platform)
        internal
        view
        virtual
        returns (address verifier);

    function _platformMapToWebAuthNverifier(WebAuthNAttestPlatform platform)
        internal
        view
        virtual
        returns (address verifier);

    function _attestWebAuthn(WebAuthNAttestationSchema memory att) internal virtual returns (bytes32 attestationId);

    function _attestNative(NativeAttestationSchema memory att, uint256 expiry)
        internal
        virtual
        returns (bytes32 attestationId);
}
