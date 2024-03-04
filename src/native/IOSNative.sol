// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {NativeX5CBase} from "./base/NativeX5CBase.sol";
import {BytesUtils} from "../utils/BytesUtils.sol";

struct AttStmt {
    bytes[] x5c;
    // https://developer.apple.com/documentation/devicecheck/assessing-fraud-risk
    bytes receipt;
    bytes authData;
}

abstract contract IOSNative is NativeX5CBase {
    
    using BytesUtils for bytes;

    error Invalid_App_Id(bytes32 appIdFound);
    error Invalid_Count();
    error Mismatch_Key_Identifier(bytes32 keyId);

    /// @dev configure valid iOS App ID that generates the keypair
    function appId() public view virtual returns (bytes32);

    /// @dev configure the validity of the operating environment
    /// either "appattestdevelop" or "appattest" followed by 7 0x00 bytes
    function _aaguidIsValid(bytes16 aaguid) internal view virtual returns (bool);
    
    /// @dev the payload is the abi encoded of the (CBOR decoded) AttStmt Object
    function _verifyPayload(string calldata, bytes calldata payload)
        internal
        view
        override
        returns (bytes memory attestationData)
    {
        AttStmt memory attStmt = abi.decode(payload, (AttStmt));
        (
            bytes32 rpid,
            uint256 counter,
            bytes16 aaguid,
            bytes32 credentialId
        ) = _parseAuthData(attStmt.authData);

        if (rpid != appId()) {
            revert Invalid_App_Id(rpid);
        }

        if (counter > 0) {
            revert Invalid_Count();
        }

        (bytes memory pubKey, bytes32 nonce) = _parseCredCert(attStmt.x5c[0]);

        bytes32 keyIdFound = sha256(pubKey);
        if (keyIdFound != credentialId) {
            revert Mismatch_Key_Identifier(keyIdFound);
        }

        // TODO: Find out what the challenge is

        attestationData = abi.encode(pubKey, attStmt.receipt);
    }

    function _parseAuthData(bytes memory authData) private pure returns (
        bytes32 rpid,
        uint256 counter,
        bytes16 aaguid,
        bytes32 credentialId
    ) {
        // TODO
    }

    function _parseCredCert(bytes memory credCert) private pure returns (
        bytes memory pubKey,
        bytes32 nonce
    ) {
        // TODO
        // Extract the public key, to be hashed and compared with key identifier
        // Extract the nonce from the extension, OID 1.2.840.113635.100.8.2
    }
}