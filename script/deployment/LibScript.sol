// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/StdJson.sol";
import "forge-std/Script.sol";

import "../../src/utils/DerParser.sol";
import "../../src/utils/SigVerifyLib.sol";

struct Lib {
    address derParser;
    address sigVerifyLib;
}

contract LibScript is Script {
    uint256 internal privateKey = vm.envUint("PRIVATE_KEY");

    /// @dev Reads deployed library addresses from lib.json on the current network
    function read() internal view returns (Lib memory lib) {
        string memory dir = string.concat(
            vm.projectRoot(),
            "/script/deployment/lib"
        );
        string memory json = vm.readFile(string.concat(dir, ".json"));
        string memory chainSelector = string.concat(".", vm.toString(block.chainid));
        lib.sigVerifyLib = stdJson.readAddress(json, string.concat(chainSelector, ".SigVerifyLib"));
        lib.derParser = stdJson.readAddress(json, string.concat(chainSelector, ".DerParser"));
    }

    /// @dev This creates a new deploy.json file that contains the deployment addresses for the current network
    /// @dev The object in this json file matches the schema from lib.json
    /// @dev Currently, you must manually copy the object in deploy.json to lib.json
    /// @dev Careful: This method overwrites the content of an existing deploy.json file
    /// TODO: We need to copy everything from lib.json, and write everything back to lib.json (including the new deployment)
    /// to make it appear, as if we are appending the new deployment addresses to the exsiting ones.
    function deployLib() external {
        vm.startBroadcast(privateKey);
        DerParser derParser = new DerParser();
        SigVerifyLib sigVerifyLib = new SigVerifyLib();

        console.log("[LOG] DerParser: ", address(derParser));
        console.log("[LOG] SigVerifyLib: ", address(sigVerifyLib));

        vm.stopBroadcast();

        // string memory parent_object = "parent object";
        // string memory chainIdKey = vm.toString(block.chainid);

        // vm.serializeAddress(chainIdKey, "DerParser", address(derParser));
        // string memory output = vm.serializeAddress(chainIdKey, "SigVerifyLib", address(sigVerifyLib));

        // string memory finalJson = vm.serializeString(
        //     parent_object,
        //     chainIdKey,
        //     output
        // );

        // string memory dir = string.concat(
        //     vm.projectRoot(),
        //     "/script/deployment/deploy"
        // );
        // string memory path = string.concat(dir, ".json");
        // vm.writeFile(path, finalJson);
    }
}