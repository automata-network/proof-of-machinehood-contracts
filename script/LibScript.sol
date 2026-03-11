// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {X509ChainVerifier, IRiscZeroVerifier} from "@automata-network/risc0-zk-x509/X509ChainVerifier.sol";

import "./utils/DeploymentConfig.sol";

import "../src/utils/DerParser.sol";
import "../src/utils/SigVerifyLib.sol";

contract LibScript is DeploymentConfig {

    address deployer = vm.envAddress("DEPLOYER");
    address risc0Router = vm.envOr(
        "RISC0_UNIVERSAL_ROUTER_ADDRESS", 
        0xaE7F7EC735b6A90366e55f87780b36e7e6Ec3c65 // ATA Testnet
    );
    bytes32 X509_VERIFIER_IMAGE_ID = vm.envOr(
        "X509_VERIFIER_IMAGE_ID", 
        bytes32(0x0e32c644e95e18e497d65ecf4d01ed26ce1fd2cfcfa9d2dbb37881a79c6fcce4)
    );

    function run() external {
        vm.startBroadcast(deployer);
        DerParser derParser = new DerParser();
        SigVerifyLib sigVerifyLib = new SigVerifyLib();

        console.log("[LOG] DerParser: ", address(derParser));
        console.log("[LOG] SigVerifyLib: ", address(sigVerifyLib));

        vm.stopBroadcast();

        if (readContractAddress("X509ChainVerifier", false) == address(0)) {
            deployX509Verifier();
        }

        writeToJson("DerParser", address(derParser));
        writeToJson("SigVerifyLib", address(sigVerifyLib));
    }

    function deployX509Verifier() public {
        vm.startBroadcast(deployer);
        X509ChainVerifier x509Verifier = new X509ChainVerifier(IRiscZeroVerifier(risc0Router));
        x509Verifier.setImageId(X509_VERIFIER_IMAGE_ID);
        console.log("[LOG] X509ChainVerifier: ", address(x509Verifier));
        vm.stopBroadcast();

        writeToJson("X509ChainVerifier", address(x509Verifier));
    }

    function updateX509VerifierImageId(bytes32 newImageId) public {
        address x509VerifierAddress = readContractAddress("X509ChainVerifier", true);
        X509ChainVerifier x509Verifier = X509ChainVerifier(x509VerifierAddress);
        vm.startBroadcast(deployer);
        x509Verifier.setImageId(newImageId);
        console.log("[LOG] Updated X509ChainVerifier Image ID to: ");
        console.logBytes32(newImageId);
        vm.stopBroadcast();
    }
}
