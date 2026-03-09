// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "../utils/DeploymentConfig.sol";
import {AutomataPOMEntrypoint, NativeAttestPlatform, WebAuthNAttestPlatform} from "../../src/example/AutomataPOMEntrypoint.sol";

contract EntrypointScript is DeploymentConfig {
    AutomataPOMEntrypoint entrypoint;
    TransparentUpgradeableProxy proxy;
    address deployer = vm.envAddress("DEPLOYER");
    address adminOwner = vm.envAddress("PROXY_ADMIN_OWNER");

    function deployEntrypointImpl() public {
        vm.broadcast(deployer);
        entrypoint = new AutomataPOMEntrypoint();
        writeToJson("AutomataPOMEntrypointImpl", address(entrypoint));
    }

    function deployEntrypoint(address impl) public {
        vm.broadcast(deployer);
        if (impl == address(0) && readContractAddress("AutomataPOMEntrypointImpl", false) == address(0)) {
            entrypoint = new AutomataPOMEntrypoint();
            writeToJson("AutomataPOMEntrypointImpl", address(entrypoint));
        } else {
            entrypoint = AutomataPOMEntrypoint(impl);
        }

        bytes memory initData = abi.encodeWithSelector(AutomataPOMEntrypoint.initialize.selector, deployer);

        vm.broadcast(adminOwner);
        proxy = new TransparentUpgradeableProxy(address(entrypoint), adminOwner, initData);
        writeToJson("AutomataPOMEntrypointProxy", address(proxy));
    }

    function upgradeEntrypoint(address implAddr, bytes memory data) public {
        address entrypointAddr;
        if (implAddr == address(0)) {
            entrypoint = new AutomataPOMEntrypoint();
            writeToJson("AutomataPOMEntrypointImpl", address(entrypoint));
            entrypointAddr = address(entrypoint);
        } else {
            entrypointAddr = implAddr;
        }
        address proxyAdminAddr = readContractAddress("ProxyAdmin", true);

        ProxyAdmin proxyAdmin = ProxyAdmin(proxyAdminAddr);

        vm.startBroadcast(adminOwner);

        AutomataPOMEntrypoint impl = new AutomataPOMEntrypoint();
        proxyAdmin.upgradeAndCall(ITransparentUpgradeableProxy(entrypointAddr), address(impl), data);
    
        vm.stopBroadcast();
    }

    function configEntrypointForNative(uint8 platform, address verifier) public {
        address entrypointAddr = readContractAddress("AutomataPOMEntrypointProxy", true);

        entrypoint = AutomataPOMEntrypoint(entrypointAddr);

        vm.broadcast(deployer);
        entrypoint.setNativeAttVerifier(NativeAttestPlatform(platform), verifier);
    }
}
