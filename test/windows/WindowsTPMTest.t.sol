// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "./WindowsTPMConstants.sol";
import "../../src/WindowsTPM.sol";
import "../../src/utils/DerParser.sol";
import "../../src/utils/SigVerifyLib.sol";

contract WindowsTPMTest is Test, WindowsTPMConstants {
    WindowsTPM attestationContract;
    DerParser derParser;
    SigVerifyLib sigVerify;

    address admin = address(1); // arbitrary admin to configure trusted CA chain

    function setUp() public {
        vm.startPrank(admin);

        derParser = new DerParser();
        sigVerify = new SigVerifyLib();
        attestationContract = new WindowsTPM(address(sigVerify), address(derParser));
        attestationContract.addCACert(certHash);

        vm.stopPrank();

        // Bypass Expired Certificate reverts
        // October 12th, 2023, 12:30:00 GMT+8
        vm.warp(1697085000);
    }

    function testWindowsTPMAttestation() public {
        address wallet = 0x64188ea52BaF4B724E658036A339facC4F2ed723;
        // bytes memory challenge = hex"000000000000000000000000dc3bda6d40f0e33e0dfa4aef9604b66195e6c5dc00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000a4b10000000000000000000000000000000000000000000000000000000000000000";
        bytes memory challenge = abi.encode(wallet);
        (bool verified,) = attestationContract.verifyAttStmt(challenge, encodedAttStmt, authData, clientDataJSON);
        assertTrue(verified);
    }
}
