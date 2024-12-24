// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {NativeBase} from "./base/NativeBase.sol";
import {LibString} from "solady/utils/LibString.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

import {BytesUtils} from "../utils/BytesUtils.sol";
import {ISigVerifyLib} from "../utils/interfaces/ISigVerifyLib.sol";

abstract contract MacNative is NativeBase {
    using LibString for *;
    using ECDSA for bytes32;
    using BytesUtils for bytes;

    error Invalid_Chain_Id();
    error Expired();
    error Invalid_Device_Id();
    error Invalid_TEE_Signer(address recovered);

    ISigVerifyLib public immutable sigVerifyLib;

    constructor(address _sigVerifyAddr) {
        sigVerifyLib = ISigVerifyLib(_sigVerifyAddr);
    }

    /// @dev extend this getter method to check whether the input address is
    /// derived from a trusted TEE signing key
    function trustedSigningKey(address key) public view virtual returns (bool);

    function verifyAssertion(bytes calldata attestedPubKey, bytes calldata clientData, bytes calldata assertionPayload)
        external
        view
        override
        returns (bool)
    {
        (bytes memory signature, bytes memory teeSignature) = abi.decode(assertionPayload, (bytes, bytes));
        bool sigVerified = sigVerifyLib.verifyES256Signature(clientData, signature, attestedPubKey);
        if (!sigVerified) {
            return false;
        }
        bytes32 teeDigest = keccak256(signature);
        address recovered = teeDigest.recover(teeSignature);
        return trustedSigningKey(recovered);
    }

    /// @dev deviceIdentity is the public portion of the attested secp256k1 key
    /// @return attestationData the attested pubkey to be stored on-chain
    function _verifyPayload(bytes calldata deviceIdentity, bytes[] calldata payload)
        internal
        view
        override
        returns (bytes memory attestationData, uint256 expiry)
    {
        (bytes memory encodedMessageBytes, bytes memory signature) = abi.decode(payload[0], (bytes, bytes));
        bytes memory pubKey;
        (pubKey, expiry) = abi.decode(encodedMessageBytes, (bytes, uint256));

        // Check expiredAt
        if (expiry < block.timestamp) {
            revert Expired();
        }

        // Check deviceIdentity == hex(pubKey)
        if (!pubKey.equals(deviceIdentity)) {
            revert Invalid_Device_Id();
        }

        // verify signature
        bytes32 digest = keccak256(encodedMessageBytes);
        address recovered = digest.recover(signature);
        if (!trustedSigningKey(recovered)) {
            revert Invalid_TEE_Signer(recovered);
        }

        attestationData = pubKey;
    }
}
