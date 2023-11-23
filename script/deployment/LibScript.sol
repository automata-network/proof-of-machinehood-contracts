// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/StdJson.sol";
import "forge-std/Script.sol";

struct Lib {
    address derParser;
    address sigVerifyLib;
}

contract LibScript is Script {
    function read() internal view returns (Lib memory lib) {
        string memory inputDir = string.concat(
            vm.projectRoot(),
            "/script/deployment/lib"
        );
        string memory json = vm.readFile(string.concat(inputDir, ".json"));
        string memory chainSelector = string.concat(".", vm.toString(block.chainid));
        lib.sigVerifyLib = stdJson.readAddress(json, string.concat(chainSelector, ".SigVerifyLib"));
        lib.derParser = stdJson.readAddress(json, string.concat(chainSelector, ".DerParser"));
    }

    // TODO: Read and copy all existing lib deployments
    // TODO: Write new deployment address to lib.json
    // function write(string memory name, address libAddr) internal {
    //     string memory inputDir = string.concat(
    //         vm.projectRoot(),
    //         "/script/deployment/deployed"
    //     );
    //     string memory json = vm.readFile(string.concat(inputDir, ".json"));

    //     string memory parent_object = "parent object";
    //     string memory chainIdKey = vm.toString(block.chainid);

    //     string memory output = vm.serializeAddress(chainIdKey, name, libAddr);

    //     string memory finalJson = vm.serializeString(
    //         parent_object,
    //     )
    // }
}