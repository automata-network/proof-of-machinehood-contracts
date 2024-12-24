// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

abstract contract NativeBase {
    function verifyAndGetAttestationData(bytes calldata deviceIdentity, bytes[] calldata payload)
        external
        returns (bytes memory attestedData, uint256 expiry)
    {
        (attestedData, expiry) = _verifyPayload(deviceIdentity, payload);
    }

    /**
     * @notice Performs verification on the given assertion, usually applies
     * for devices with prior attestations
     * @param attestedPubKey - NOTE: It is the caller's responsibility to check
     * the attestation status of the given public key.
     * @dev attestedPubKey must be UNPREFIXED and UNCOMPRESSED, e.g. 64 bytes,
     * consisting of concatenated X and Y coordinates
     * @param clientData  - the data or challenge
     * @param assertionPayload - payload data essential for the verification, such as a signature
     */
    function verifyAssertion(bytes calldata attestedPubKey, bytes calldata clientData, bytes calldata assertionPayload)
        external
        view
        virtual
        returns (bool);

    function _verifyPayload(bytes calldata deviceIdentity, bytes[] calldata payload)
        internal
        virtual
        returns (bytes memory attestationData, uint256 expiry);
}
