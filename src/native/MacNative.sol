// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {NativeBase} from "./base/NativeBase.sol";
import {LibString} from "solady/utils/LibString.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

abstract contract MacNative is NativeBase {
    using LibString for *;
    using ECDSA for bytes32;

    error Invalid_Chain_Id();
    error Expired();
    error Invalid_Device_Id();
    error Invalid_Signer(address recovered);

    /// @dev extend this getter method to check whether the input address is
    /// derived from a trusted TEE signing key
    function trustedSigningKey(address key) public view virtual returns (bool);

    /// @dev deviceIdentity is the public portion of the attested secp256k1 key
    /// @dev prefix deviceIdentity with 0x (cheaper for performing string comparison)
    /// @return attestationData the attested pubkey to be stored on-chain
    function _verifyPayload(string calldata deviceIdentity, bytes calldata payload)
        internal
        view
        override
        returns (bytes memory attestationData)
    {
        (bytes memory encodedMessageBytes, bytes memory signature) = abi.decode(payload, (bytes, bytes));
        (uint256 chainId, bytes memory pubKey, uint256 expiredAt) =
            abi.decode(encodedMessageBytes, (uint256, bytes, uint256));

        // Check chainId
        if (chainId != block.chainid) {
            revert Invalid_Chain_Id();
        }

        // Check expiredAt
        if (expiredAt < block.timestamp) {
            revert Expired();
        }

        // Check deviceIdentity == hex(pubKey)
        string memory pubkeyHex = pubKey.toHexString();
        if (!pubkeyHex.eq(deviceIdentity)) {
            revert Invalid_Device_Id();
        }

        // verify signature
        bytes32 digest = keccak256(encodedMessageBytes);
        address recovered = digest.recover(signature);
        if (!trustedSigningKey(recovered)) {
            revert Invalid_Signer(recovered);
        }

        attestationData = pubKey;
    }
}
