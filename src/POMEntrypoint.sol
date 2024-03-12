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
    YUBIKEY
}

struct ValidationPayloadStruct {
    bytes attStmt;
    bytes authData;
    bytes clientData;
}

abstract contract POMEntrypoint {

    error Missing_Verifier_Or_Platform_Unsupported();

    function nativeAttest(
        NativeAttestPlatform platform, 
        bytes calldata deviceIdentity, 
        bytes[] calldata payload
    ) external returns (bytes32 attestationId) {
        address verifier = _platformMapToNativeVerifier(platform);
        if (verifier == address(0)) {
            revert Missing_Verifier_Or_Platform_Unsupported();
        }
        bytes memory attestedData = NativeBase(verifier).verifyAndGetAttestationData(deviceIdentity, payload);
        attestationId = _attest(attestedData);
    }

    function webAuthNAttest(
        WebAuthNAttestPlatform platform,
        bytes32 walletAddress,
        ValidationPayloadStruct calldata validationPayload
    ) external returns (bytes32 attestationId) {
        address verifier = _platformMapToWebAuthNverifier(platform);
        if (verifier == address(0)) {
            revert Missing_Verifier_Or_Platform_Unsupported();
        }
        (bool success, string memory reason) = AttestationVerificationBase(verifier).verifyAttStmt(
            abi.encodePacked(walletAddress), validationPayload.attStmt, validationPayload.authData, validationPayload.clientData
        );
        require(success, reason);
        bytes32 proofHash = keccak256(abi.encodePacked(validationPayload.attStmt, validationPayload.authData, validationPayload.clientData));
        attestationId = _attest(abi.encodePacked(proofHash));
    }

    function _platformMapToNativeVerifier(NativeAttestPlatform platform) internal virtual view returns (address verifier);

    function _platformMapToWebAuthNverifier(WebAuthNAttestPlatform platform) internal virtual view returns (address verifier);

    function _attest(bytes memory attestationData) internal virtual returns (bytes32 attestationId);
}