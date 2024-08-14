// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {ISigVerifyLib} from "../../utils/interfaces/ISigVerifyLib.sol";
import {BytesUtils} from "../../utils/BytesUtils.sol";
import {NodePtr} from "../../utils/Asn1Decode.sol";

import {NativeBase} from "./NativeBase.sol";
import {X509Helper, X509CertObj, PublicKeyAlgorithm, SignatureAlgorithm} from "../x509/X509Helper.sol";

import {X509ChainVerifier} from "@automata-network/risc0-zk-x509/X509ChainVerifier.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

enum ProverType {
    ZK,
    TEE
}

abstract contract NativeX5CBase is NativeBase {
    using BytesUtils for bytes;
    using NodePtr for uint256;
    using ECDSA for bytes32;

    ISigVerifyLib public immutable sigVerifyLib;
    X509ChainVerifier public x509Verifier;

    constructor(address _sigVerifyAddr, address _x509Verifier) {
        sigVerifyLib = ISigVerifyLib(_sigVerifyAddr);
        x509Verifier = X509ChainVerifier(_x509Verifier);
    }

    error Unauthorized_Tee_Address(address recovered);

    function addCACert(bytes32 hash) external virtual {}

    function removeCACert(bytes32 hash) external virtual {}

    function caIsTrusted(bytes32 hash) public view virtual returns (bool) {}

    function setTrustedTee(address tee, bool trusted) external virtual {}

    function teeIsTrusted(address tee) public view virtual returns (bool) {}

    function updateX509Verifier(address _x509Verifier) public virtual {}

    function _checkX509Proof(bytes[] memory x5c, bytes memory seal) internal view {
        // risc0 reverts if failed
        x509Verifier.verifyX509ChainProof(x5c, seal);
    }

    function _checkTeeProof(bytes[] memory x5c, bytes memory sig) internal view {
        bytes32 chainHash = sha256(abi.encode(x5c));
        bytes32 rootHash = sha256(x5c[x5c.length - 1]);
        bytes32 digest = keccak256(abi.encode(chainHash, rootHash, true));

        // ecrecover
        address recovered = digest.recover(sig);
        if (!teeIsTrusted(recovered)) {
            revert Unauthorized_Tee_Address(recovered);
        }
    }

    /**
     * @notice Either pads or trims the input, depending on the expected length
     * @param content - the input
     * @param expectedLength - the length of the processed data
     * @dev This method works as the following:
     * - if the input is longer than the expected length (usually it's padded with leading zeros), trim off most-significant
     * bytes;
     * - if the input is shorter than the expected length, pads zeros at the front until it reaches the expected length
     */
    function _process(bytes memory content, uint256 expectedLength) internal pure returns (bytes memory) {
        uint256 len = content.length;
        if (len > expectedLength) {
            uint256 lengthDiff = len - expectedLength;
            return content.substring(lengthDiff, expectedLength);
        } else if (len < expectedLength) {
            uint256 lengthDiff = expectedLength - len;
            bytes memory padZero = new bytes(lengthDiff);
            return abi.encodePacked(padZero, content);
        }
        return content;
    }

    /// @dev if a tag belongs to the context-specific class (8th bit = 1, 7th bit = 0)
    /// that means a content is being tagged with a number in square brackets, [N]
    /// if N > 30 (11110), the tag is encoded in long form
    /// @return offset - the position of the last tag byte
    /// @return context - the context number that the content is tagged with
    function _getContextNumberFromTag(bytes memory der) internal pure returns (uint256 offset, uint256 context) {
        bool isContextSpecific = der[0] & 0x80 == 0x80;
        require(isContextSpecific, "provided DER does not have a context-specific tag");
        bytes1 val = der[0] & 0x1f;
        bool tagIsLong = val == 0x1f;
        if (tagIsLong) {
            offset = 1;
            bool stop = der[offset] & 0x80 == 0x00;
            while (!stop) {
                context += uint8(bytes1(der[offset] & 0x7f));
                context <<= 7;
                stop = der[++offset] & 0x80 == 0x00;
            }
            context += uint8(bytes1(der[offset] & 0x7f));
        } else {
            context = uint8(val);
        }
    }

    /// Modified from Asn1Decode.sol to accommodate long-form tags
    /// @param ix refers to the index of the last tag byte
    function _readNodeLength(bytes memory der, uint256 ix, uint256 tagSize) internal pure returns (uint256) {
        uint256 length;
        uint80 ixFirstContentByte;
        uint80 ixLastContentByte;
        if ((der[ix + 1] & 0x80) == 0) {
            length = uint8(der[ix + 1]);
            ixFirstContentByte = uint80(ix + 2);
            ixLastContentByte = uint80(ixFirstContentByte + length - 1);
        } else {
            uint8 lengthbytesLength = uint8(der[ix + 1] & 0x7F);
            if (lengthbytesLength == 1) {
                length = der.readUint8(ix + 2);
            } else if (lengthbytesLength == 2) {
                length = der.readUint16(ix + 2);
            } else {
                length = uint256(der.readBytesN(ix + 2, lengthbytesLength) >> (32 - lengthbytesLength) * 8);
            }
            ixFirstContentByte = uint80(ix + 2 + lengthbytesLength);
            ixLastContentByte = uint80(ixFirstContentByte + length - 1);
        }
        return NodePtr.getPtr(ix + 1 - tagSize, ixFirstContentByte, ixLastContentByte);
    }
}
