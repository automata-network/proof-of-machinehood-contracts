// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "../src/webauthn/AndroidSafetyNet.sol";
import "../src/webauthn/WindowsTPM.sol";
import "../src/webauthn/Yubikey.sol";
import "./utils/DeploymentConfig.sol";

contract Deploy is DeploymentConfig {
    address deployer = vm.envAddress("DEPLOYER");
    address sigVerifyLib = readContractAddress("SigVerifyLib", true);
    address derParser = readContractAddress("DerParser", true);

    function run() public {
        deployAndroidSafetyNet();
        deployWindowsTPM();
        deployYubikey();
    }

    function deployAndroidSafetyNet() public {
        vm.startBroadcast(deployer);
        AndroidSafetyNet attestation = new AndroidSafetyNet(sigVerifyLib, derParser);

        // Issuer: GTS Root R1
        // Subject: GTS CA 104
        bytes32 certHash = 0xb9d623ec16695de2060578bef9e4df7966f57c618bc5ea62634976f15296ff15;
        attestation.addCACert(certHash);

        // Issuer: GlobalSign RootCA
        // Subject: GTS Root R1
        bytes32 rootHash = 0x333cfe96a08b17e6221d85230c42cac1aedb8558ba3558bc94820a828147c978;
        attestation.addCACert(rootHash);

        vm.stopBroadcast();

        console.log("[LOG] AndroidSafetyNet: ", address(attestation));
    }

    function deployWindowsTPM() public {
        vm.startBroadcast(deployer);
        WindowsTPM attestation = new WindowsTPM(sigVerifyLib, derParser);

        bytes32 certHash = 0x0ef49ca16946643d989b177d16eead1db8992f51b1046bb7a0177d6650d8f23f;
        attestation.addCACert(certHash);
        vm.stopBroadcast();

        console.log("[LOG] WindowsTPM: ", address(attestation));
    }

    function deployYubikey() public {
        vm.startBroadcast(deployer);
        Yubikey attestation = new Yubikey(sigVerifyLib, derParser);

        bytes32 certHash = 0x18c535288d76f1259167f42ff52cd5516e5ac0900d5708fd8e6e6276e64fda12;
        attestation.addCACert(certHash);
        vm.stopBroadcast();

        console.log("[LOG] Yubikey: ", address(attestation));
    }
}
