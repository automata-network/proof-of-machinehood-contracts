// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "../utils/DeploymentConfig.sol";

import "../../src/example/AutomataAndroidNativePOM.sol";
import "../../src/example/AutomataIosNativePOM.sol";
import "../../src/example/AutomataMacNativePOM.sol";

contract DeployNativeScript is DeploymentConfig {
    AutomataMacNativePOM mac;
    AutomataIosNativePOM ios;
    AutomataAndroidNativePOM android;
    address deployer = vm.envAddress("DEPLOYER");
    address sigVerifyLib = readContractAddress("SigVerifyLib", true);
    address x509Risc0 = readContractAddress("X509ChainVerifier", true);

    function deployMacNative() public {
        vm.broadcast(deployer);
        mac = new AutomataMacNativePOM(sigVerifyLib);
        writeToJson("AutomataMacNativePOM", address(mac));
    }

    function deployAndroidNative() public {
        vm.broadcast(deployer);
        android = new AutomataAndroidNativePOM(sigVerifyLib, x509Risc0);

        // known hashes — sha256(rootCertDer) for each Google attestation root
        // legacy factory-provisioned RSA-4096 root (serialNumber=f92009e853b6b045, valid 2019-2034)
        android.addCACert(0x1ef1a04b8ba58ab94589ac498c8982a783f24ea7307e0159a0c3a73b377d87cc);
        // current factory-provisioned RSA-4096 root (published at https://android.googleapis.com/attestation/root)
        android.addCACert(0xcedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc);
        // additional legacy Google attestation root
        android.addCACert(0xab6641178a36e179aa0c1cdddf9a16eb45fa20943e2b8cd7c7c05c26cf8b487a);
        // Remote Key Provisioning (RKP) root "Key Attestation CA1", ECDSA P-384 (valid 2025-07-17 to 2035-07-15)
        // signs attestation chains for RKP-enabled devices starting 2026-02-01
        android.addCACert(0x6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0);

        vm.stopBroadcast();

        writeToJson("AutomataAndroidNativePOM", address(android));
    }

    function deployIosNative(string calldata bundleId) public {
        bytes32 appId = sha256(bytes(bundleId));

        vm.broadcast(deployer);
        ios = new AutomataIosNativePOM(sigVerifyLib, x509Risc0, appId);

        bytes32 rootHash = 0x1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932;
        ios.addCACert(rootHash);

        vm.stopBroadcast();
        writeToJson("AutomataIosNativePOM", address(ios));
    }
}
