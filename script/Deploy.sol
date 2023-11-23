// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "../src/AndroidSafetyNet.sol";
import "../src/WindowsTPM.sol";
import "../src/Yubikey.sol";
import "./deployment/LibScript.sol";

contract Deploy is LibScript {
    function deployAndroidSafetyNet() public {
        vm.broadcast(privateKey);
        Lib memory lib = read();
        new AndroidSafetyNet(lib.sigVerifyLib, lib.derParser);
        vm.stopBroadcast();
    }

    function deployWindowsTPM() public {
        vm.broadcast(privateKey);
        Lib memory lib = read();
        new WindowsTPM(lib.sigVerifyLib, lib.derParser);
        vm.stopBroadcast();
    }

    function deployYubikey() public {
        vm.broadcast(privateKey);
        Lib memory lib = read();
        new Yubikey(lib.sigVerifyLib, lib.derParser);
        vm.stopBroadcast();
    }
}