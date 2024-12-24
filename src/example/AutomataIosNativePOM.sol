// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import {IOSNative, IOSPayload, IOSAssertionPayload} from "../native/IOSNative.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {X509ChainVerifier} from "@automata-network/risc0-zk-x509/X509ChainVerifier.sol";

contract AutomataIosNativePOM is IOSNative, Ownable {
    /// === aaguid constants ===

    // bytes("appattestdevelop")
    bytes16 constant DEVELOPMENT_AAGUID = 0x617070617474657374646576656c6f70;
    // bytes("appattest") followed by 7 0x0 bytes
    bytes16 constant PRODUCTION_AAGUID = 0x61707061747465737400000000000000;

    bytes32 _appIdHash;
    mapping(bytes32 => bool) _trustedCAs;
    mapping(address => bool) _teeTrusted;

    constructor(address _sigVerifyLib, address _x509Verifier, bytes32 _appId) IOSNative(_sigVerifyLib, _x509Verifier) {
        _initializeOwner(msg.sender);
        _appIdHash = _appId;
    }

    function addCACert(bytes32 hash) external override onlyOwner {
        _trustedCAs[hash] = true;
    }

    function removeCACert(bytes32 hash) external override onlyOwner {
        _trustedCAs[hash] = false;
    }

    function caIsTrusted(bytes32 hash) public view override returns (bool) {
        return _trustedCAs[hash];
    }

    function setTrustedTee(address tee, bool trusted) external override onlyOwner {
        _teeTrusted[tee] = trusted;
    }

    function updateX509Verifier(address _x509Verifier) public override onlyOwner {
        x509Verifier = X509ChainVerifier(_x509Verifier);
    }

    function teeIsTrusted(address tee) public view override returns (bool) {
        return _teeTrusted[tee];
    }

    function setAppIdHash(bytes32 id) external onlyOwner {
        _appIdHash = id;
    }

    function appIdHash() public view override returns (bytes32) {
        return _appIdHash;
    }

    /// @dev configure the validity of the operating environment
    /// either "appattestdevelop" or "appattest" followed by 7 0x00 bytes
    /// the default behavior accepts both envrionments
    function _aaguidIsValid(bytes16 aaguid) internal pure override returns (bool) {
        return aaguid == DEVELOPMENT_AAGUID || aaguid == PRODUCTION_AAGUID;
    }
}
