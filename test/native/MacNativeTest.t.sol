// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../../src/example/AutomataMacNativePOM.sol";
import "../../src/example/AutomataPOMEntrypoint.sol";

contract MacNativeTest is Test {
    AutomataPOMEntrypoint entrypoint;
    AutomataMacNativePOM attestation;

    address constant tee = 0x9f4649C074814246b83Ea9a1e2e9aF923E8F92AE;
    address constant admin = address(1);

    function setUp() public {
        // Apr 5th, 2024 9:40am UTC
        vm.warp(1712275200);

        vm.startPrank(admin);

        entrypoint = new AutomataPOMEntrypoint();
        attestation = new AutomataMacNativePOM();

        entrypoint.setNativeAttVerifier(NativeAttestPlatform.MACOS, address(attestation));
        attestation.configureTrustedKey(tee, true);

        vm.stopPrank();
    }

    function testMacNativeConfig() public {
        assertTrue(attestation.trustedSigningKey(tee));
    }

    function testMacNativeAttestation() public {
        bytes memory att =
            hex"0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000066a11133000000000000000000000000000000000000000000000000000000000000004104f9169b1c649e789b970cbbcba5125e6cd54811b35a21b8c96c0f59610033d051d2ee6d471bfe7b1dfd70cd88d28cf9128cd31995ee210430fec6576dc20077ce000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041f7c30d169bf5f9ae797ef0b5bb20140aaec90ece9540cbbc11f9dd9a0051d0a1757e0b89df72d69d12ed31f752abec5c022243eaba6233a0d662853374291aad1c00000000000000000000000000000000000000000000000000000000000000";
        bytes memory pubkey =
            hex"04f9169b1c649e789b970cbbcba5125e6cd54811b35a21b8c96c0f59610033d051d2ee6d471bfe7b1dfd70cd88d28cf9128cd31995ee210430fec6576dc20077ce";

        bytes[] memory payload = new bytes[](1);
        payload[0] = att;

        bytes32 attestationId = entrypoint.nativeAttest(NativeAttestPlatform.MACOS, pubkey, payload);
        AttestationStatus status;
        (attestationId, status) = entrypoint.getNativeAttestationStatus(pubkey);
        assertEq(uint8(status), uint8(AttestationStatus.REGISTERED));
    }
}