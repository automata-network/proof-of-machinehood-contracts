// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "../../src/example/AutomataPOMEntrypoint.sol";

contract EntrypointScript is Script {
    AutomataPOMEntrypoint entrypoint;
    uint256 privateKey = vm.envUint("PRIVATE_KEY");

    function deployEntrypoint() public {
        vm.broadcast(privateKey);
        entrypoint = new AutomataPOMEntrypoint();
    }

    function configEntrypointForNative(uint8 platform, address verifier) public {
        address entrypointAddr = vm.envAddress("POM_ENTRYPOINT_ADDRESS");
        
        entrypoint = AutomataPOMEntrypoint(entrypointAddr);

        vm.broadcast(privateKey);
        entrypoint.setNativeAttVerifier(NativeAttestPlatform(platform), verifier);
    }
}