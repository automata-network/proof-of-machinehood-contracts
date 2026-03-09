// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./utils/DeploymentConfig.sol";

import "../src/utils/DerParser.sol";
import "../src/utils/SigVerifyLib.sol";

contract LibScript is DeploymentConfig {

    address deployer = vm.envAddress("DEPLOYER");

    function run() external {
        vm.startBroadcast(deployer);
        DerParser derParser = new DerParser();
        SigVerifyLib sigVerifyLib = new SigVerifyLib();

        console.log("[LOG] DerParser: ", address(derParser));
        console.log("[LOG] SigVerifyLib: ", address(sigVerifyLib));

        vm.stopBroadcast();

        writeToJson("DerParser", address(derParser));
        writeToJson("SigVerifyLib", address(sigVerifyLib));
    }
}
