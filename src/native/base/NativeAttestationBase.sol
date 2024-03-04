// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

abstract contract NativeAttestationBase {

    function getDeviceAttestation(string calldata deviceIdentity) public view virtual returns (bytes32 attestationId);

    function _verifyPayload(string calldata deviceIdentity, bytes calldata payload) internal virtual;
    
    function _attest(string calldata deviceIdentity, bytes calldata payload)
        internal
        virtual
        returns (bytes32 attestationId) 
    {}
}
