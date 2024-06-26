// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../../src/example/AutomataAndroidNativePOM.sol";
import "../../src/example/AutomataIosNativePOM.sol";
import "../../src/example/AutomataMacNativePOM.sol";

interface IX509 {
    function addCACert(bytes32 hash) external;

    function removeCACert(bytes32 hash) external;

    function setTrustedTee(address tee, bool trusted) external;
}

contract ConfigNativeScript is Script {
    AutomataMacNativePOM mac = AutomataMacNativePOM(vm.envAddress("NATIVE_MACOS_ADDRESS"));
    AutomataIosNativePOM ios = AutomataIosNativePOM(vm.envAddress("NATIVE_IOS_ADDRESS"));
    AutomataAndroidNativePOM android = AutomataAndroidNativePOM(vm.envAddress("NATIVE_ANDROID_ADDRESS"));
    uint256 privateKey = vm.envUint("PRIVATE_KEY");

    modifier broadcastKey() {
        vm.startBroadcast(privateKey);
        _;
        vm.stopBroadcast();
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
