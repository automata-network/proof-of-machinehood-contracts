// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "forge-std/Script.sol";
import {AutomataPOMEntrypoint, NativeAttestPlatform} from "../../src/example/AutomataPOMEntrypoint.sol";

contract EntrypointScript is Script {
    AutomataPOMEntrypoint entrypoint;
    TransparentUpgradeableProxy proxy;
    uint256 privateKey = vm.envUint("PRIVATE_KEY");
    uint256 adminPrivateKey = vm.envUint("PROXY_ADMIN_KEY");

    function deployEntrypoint() public {
        vm.broadcast(privateKey);
        entrypoint = new AutomataPOMEntrypoint();

        bytes memory initData = abi.encodeWithSelector(
            AutomataPOMEntrypoint.initialize.selector,
            vm.addr(privateKey)
        );
        
        address adminAddr = vm.addr(adminPrivateKey);
        vm.broadcast(adminPrivateKey);
        proxy = new TransparentUpgradeableProxy(address(entrypoint), adminAddr, initData);
    }

    function deployEntrypointImplOnly() public {
        vm.broadcast(privateKey);
        entrypoint = new AutomataPOMEntrypoint();
    }

    function deployProxy(address impl) public {
        bytes memory initData = abi.encodeWithSelector(
            AutomataPOMEntrypoint.initialize.selector,
            vm.addr(privateKey)
        );
        
        address adminAddr = vm.addr(adminPrivateKey);
        vm.broadcast(adminPrivateKey);
        proxy = new TransparentUpgradeableProxy(impl, adminAddr, initData);
    }

    function configEntrypointForNative(uint8 platform, address verifier) public {
        address entrypointAddr = vm.envAddress("POM_ENTRYPOINT_ADDRESS");

        entrypoint = AutomataPOMEntrypoint(entrypointAddr);

        vm.broadcast(privateKey);
        entrypoint.setNativeAttVerifier(NativeAttestPlatform(platform), verifier);
    }

    function upgradePom(address impl, bytes memory data) public {
        address entrypointAddr = vm.envAddress("POM_ENTRYPOINT_ADDRESS");
        address proxyAdminAddr = vm.envAddress("PROXY_ADMIN_ADDR");

        ProxyAdmin proxyAdmin = ProxyAdmin(proxyAdminAddr);

        vm.broadcast(adminPrivateKey);
        proxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(entrypointAddr),
            impl,
            data
        );
    }
}
