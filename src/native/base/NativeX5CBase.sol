// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {ISigVerifyLib} from "../../utils/interfaces/ISigVerifyLib.sol";
import {BytesUtils} from "../../utils/BytesUtils.sol";

import {NativeBase} from "./NativeBase.sol";
import {X509Helper, X509CertObj, PublicKeyAlgorithm, SignatureAlgorithm} from "../x509/X509Helper.sol";

import {X509ChainVerifier} from "@automata-network/x509-zk-verifier/X509ChainVerifier.sol";

struct Risc0ProofObj {
    bytes32 postStateDigest;
    bytes seal;
}

abstract contract NativeX5CBase is NativeBase {
    using BytesUtils for bytes;

    ISigVerifyLib public immutable sigVerifyLib;
    X509ChainVerifier public immutable x509Verifier;

    constructor(address _sigVerifyAddr, address _x509Verifier) {
        sigVerifyLib = ISigVerifyLib(_sigVerifyAddr);
        x509Verifier = X509ChainVerifier(_x509Verifier);
    }

    /// @dev The CA Hash is a bytes32 value that is computed with the SHA256 hash of the values described below:
    /// @dev The tightly packed binary value of the issuer certificate's tbs, public key and signature.abi
    /// @dev This hash is stored to indicate that the issuer certificate is to be trusted.
    /// @dev The configuration of CA hashes serve the following purposes:
    ///     1. The contract is explicitly specifying the issuer's identity, whom can be completely trusted.
    ///     2. It allows the contract to not having to perform signature verifications on every certificates in the chain,
    ///     as long as a trusted authority has been found.
    /// @notice Issuer certificates are also known as "father certs".
    mapping(bytes32 => bool) internal isCACertificate;

    function addCACert(bytes32 hash) external virtual {}

    function removeCACert(bytes32 hash) external virtual {}

    function caIsTrusted(bytes32 hash) public view virtual returns (bool) {}

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

    function _checkX509Proof(bytes[] memory x5c, Risc0ProofObj memory proof) internal view returns (bool verified) {
        verified = x509Verifier.verifyX509ChainProof(x5c, proof.postStateDigest, proof.seal);
    }
}
