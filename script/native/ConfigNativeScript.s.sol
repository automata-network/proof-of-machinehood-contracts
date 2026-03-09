// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "../utils/DeploymentConfig.sol";
import "../../src/native/base/NativeX5CBase.sol";
import "../../src/example/AutomataAndroidNativePOM.sol";
import "../../src/example/AutomataIosNativePOM.sol";
import "../../src/example/AutomataMacNativePOM.sol";

interface IX509 {
    function addCACert(bytes32 hash) external;

    function removeCACert(bytes32 hash) external;

    function setTrustedTee(address tee, bool trusted) external;

    function updateX509Verifier(address _x509Verifier) external;
}

contract ConfigNativeScript is DeploymentConfig {
    AutomataMacNativePOM mac = AutomataMacNativePOM(readContractAddress("AutomataMacNativePOM", true));
    AutomataIosNativePOM ios = AutomataIosNativePOM(readContractAddress("AutomataIosNativePOM", true));
    AutomataAndroidNativePOM android = AutomataAndroidNativePOM(readContractAddress("AutomataAndroidNativePOM", true));
    address deployer = vm.envAddress("DEPLOYER");
    address x509Risc0 = readContractAddress("X509ChainVerifier", true);

    modifier broadcastKey() {
        vm.startBroadcast(deployer);
        _;
        vm.stopBroadcast();
    }

    function updateX509(NativeX5CBase native) public broadcastKey {
        native.updateX509Verifier(x509Risc0);
    }

    function configMac(address signerKey, bool trusted) public broadcastKey {
        mac.configureTrustedKey(signerKey, trusted);
    }

    function configIos(string calldata bundleId) public broadcastKey {
        bytes32 appId = sha256(bytes(bundleId));
        ios.setAppIdHash(appId);
    }

    function configAndroidAttestationVersion(uint256 attestationVersion, bool supported) public broadcastKey {
        android.setSupportedAttestationVersions(attestationVersion, supported);
    }

    function configAndroidPackageSignature(bytes calldata signature, bool supported) public broadcastKey {
        android.setSupportedPackageSignature(signature, supported);
    }

    function configureAndroidPackageVersion(uint256 version, bool supported) public broadcastKey {
        android.setSupportedPackageVersions(version, supported);
    }

    function configureAndroidPackageName(string calldata name) public broadcastKey {
        android.setPackageName(name);
    }

    function addCaHash(address verifier, bytes32 hash) public broadcastKey {
        IX509(verifier).addCACert(hash);
    }

    function removeCaHash(address verifier, bytes32 hash) public broadcastKey {
        IX509(verifier).removeCACert(hash);
    }

    function setTrustedTee(address verifier, address tee, bool trusted) public broadcastKey {
        IX509(verifier).setTrustedTee(tee, trusted);
    }
}
