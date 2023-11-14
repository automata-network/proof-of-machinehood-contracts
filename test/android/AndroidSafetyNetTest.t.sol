// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "./AndroidSafetyNetConstants.sol";
import "../../src/AndroidSafetyNet.sol";
import "../../src/utils/DerParser.sol";
import "../../src/utils/SigVerifyLib.sol";

contract AndroidSafetyNetTest is Test, AndroidSafetyNetConstants {
    AndroidSafetyNet attestationContract;
    DerParser derParser;
    SigVerifyLib sigVerify;

    address admin = address(1); // arbitrary admin to configure trusted CA chain

    function setUp() public {
        vm.startPrank(admin);

        derParser = new DerParser();
        sigVerify = new SigVerifyLib();
        attestationContract = new AndroidSafetyNet(address(sigVerify), address(derParser));
        attestationContract.addCACert(certHash);

        vm.stopPrank();

        // Bypass Expired Certificate reverts
        // October 16th, 2023, 10:25:22AM GMT+8
        vm.warp(1697423122);
    }

    function testAndroidSafetyNetAttestation() public {
        bytes32 challenge = 0x000000000000000000000000c6219fd7c54c963a7ef13e04ef0f0d96ff826450;
        (bool verified,) = attestationContract.verifyAttStmt(challenge, encodedAttStmt, authData, clientDataJSON);
        assertTrue(verified);
    }
}
