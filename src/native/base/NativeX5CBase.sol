// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {P256} from "p256-verifier/P256.sol";

import {NativeBase} from "./NativeBase.sol";
import {X509Helper, X509CertObj} from "../x509/X509Helper.sol";

abstract contract NativeX5CBase is NativeBase {
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
}
