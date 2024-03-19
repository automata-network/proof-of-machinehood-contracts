// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

abstract contract NativeBase {
    function verifyAndGetAttestationData(bytes calldata deviceIdentity, bytes[] calldata payload)
        external
        returns (bytes memory attestedData, uint256 expiry)
    {
        (attestedData, expiry) = _verifyPayload(deviceIdentity, payload);
    }

    function _verifyPayload(bytes calldata deviceIdentity, bytes[] calldata payload)
        internal
        virtual
        returns (bytes memory attestationData, uint256 expiry);
}
