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
    WebAuthNAttestPlatform platform;
    bytes32 walletAddress;
    bytes32 proofHash;
}

struct NativeAttestationSchema {
    NativeAttestPlatform platform;
    uint64 expiry;
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
            NativeAttestationSchema({
                platform: platform,
                expiry: uint64(expiry),
                deviceIdentity: deviceIdentity,
                attData: attestedData
            })
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
            WebAuthNAttestationSchema({platform: platform, walletAddress: walletAddress, proofHash: proofHash})
        );
    }

    function webAuthNAttestationSchemaId() public view virtual returns (bytes32 WEBAUTHN_MACHINEHOOD_SCHEMA_ID);

    function nativeAttestationSchemaId() public view virtual returns (bytes32 NATIVE_MACHINEHOOD_SCHEMA_ID);

    /**
     * @notice Gets the WebAuthN attestation status and data from the given device identity
     */
    function getWebAuthNAttestationStatus(bytes32 walletAddress)
        external
        view
        virtual
        returns (AttestationStatus status, bytes memory att);

    /**
     * @notice Gets the native attestation status and data from the given device identity
     */
    function getNativeAttestationStatus(bytes calldata deviceIdentity)
        external
        view
        virtual
        returns (AttestationStatus status, bytes memory att);

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

    function _attestNative(NativeAttestationSchema memory att) internal virtual returns (bytes32 attestationId);
}
