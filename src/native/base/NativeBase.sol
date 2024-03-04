// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

abstract contract NativeBase {
    function _verifyPayload(string calldata deviceIdentity, bytes calldata payload)
        internal
        virtual
        returns (bytes memory attestationData);
}
