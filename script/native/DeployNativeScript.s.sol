// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";

import "../../src/example/AutomataAndroidNativePOM.sol";
import "../../src/example/AutomataIosNativePOM.sol";
import "../../src/example/AutomataMacNativePOM.sol";

contract DeployNativeScript is Script {
    AutomataMacNativePOM mac;
    AutomataIosNativePOM ios;
    AutomataAndroidNativePOM android;
    uint256 privateKey = vm.envUint("PRIVATE_KEY");
    address sigVerifyLib = vm.envAddress("SIG_VERIFY_LIB");
    address x509Risc0 = vm.envAddress("RISC0_X509_VERIFIER");

    function deployMacNative() public {
        vm.broadcast(privateKey);
        mac = new AutomataMacNativePOM();
    }

    function deployAndroidNative() public {
        vm.startBroadcast(privateKey);
        android = new AutomataAndroidNativePOM(sigVerifyLib, x509Risc0);

        bytes32 rootHash = 0x1ef1a04b8ba58ab94589ac498c8982a783f24ea7307e0159a0c3a73b377d87cc;
        android.addCACert(rootHash);

        vm.stopBroadcast();
    }

    function deployIosNative(string calldata bundleId) public {
        bytes32 appId = sha256(bytes(bundleId));

        vm.startBroadcast(privateKey);
        ios = new AutomataIosNativePOM(sigVerifyLib, x509Risc0, appId);

        bytes32 rootHash = 0x1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932;
        ios.addCACert(rootHash);

        vm.stopBroadcast();
    }
}