// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "../src/AndroidSafetyNet.sol";
import "../src/WindowsTPM.sol";
import "../src/Yubikey.sol";

import "forge-std/Script.sol";

// use .env addresses for now
// import "./deployment/LibScript.sol";

contract Deploy is Script {

    uint256 internal privateKey = vm.envUint("PRIVATE_KEY");
    address sigVerifyLib = vm.envAddress("SIG_VERIFY_LIB");
    address derParser = vm.envAddress("DER_PARSER");

    function deployAndroidSafetyNet() public {
        vm.startBroadcast(privateKey);
        new AndroidSafetyNet(sigVerifyLib, derParser);
        vm.stopBroadcast();
    }

    function deployWindowsTPM() public {
        vm.startBroadcast(privateKey);
        new WindowsTPM(sigVerifyLib, derParser);
        vm.stopBroadcast();
    }

    function deployYubikey() public {
        vm.startBroadcast(privateKey);
        new Yubikey(sigVerifyLib, derParser);
        vm.stopBroadcast();
    }
}