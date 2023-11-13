// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ISigVerifyLib} from "./utils/interfaces/ISigVerifyLib.sol";
import {IDerParser} from "./utils/interfaces/IDerParser.sol";
import {Ownable, Base64, JSONParserLib, LibString} from "solady/Milady.sol";

abstract contract AttestationVerificationBase is Ownable {
    using JSONParserLib for JSONParserLib.Item;
    using LibString for string;

    ISigVerifyLib public immutable sigVerify;
    IDerParser public immutable derParser;

    mapping(bytes32 => bool) internal isCACertificate;

    error Invalid_Client_Data();
    error Invalid_Challenge();

    function verifyAttStmt(bytes32 challenge, bytes memory attStmt, bytes memory authData, bytes memory clientData)
        external
        virtual
    {
        _verifyChallenge(challenge, clientData);
        _verify(attStmt, authData, clientData);
    }

    function addCACert(bytes32 hash) external onlyOwner {
        isCACertificate[hash] = true;
    }

    function removeCACert(bytes32 hash) external onlyOwner {
        isCACertificate[hash] = false;
    }

    // FUNCTIONS TO BE OVERWRITTEN

    function _verify(bytes memory attStmt, bytes memory authData, bytes memory clientData) internal virtual {}

    // HELPER FUNCTIONS

    function _verifyChallenge(bytes32 challenge, bytes memory clientData) internal pure {
        string memory clientDataJson = string(clientData);
        (,, string memory parsedChallenge) = _parseClientDataJson(clientDataJson);
        string memory encodedInputChallenge = Base64.encode(bytes(LibString.toHexString(abi.encodePacked(challenge))));
        if (!parsedChallenge.eq(encodedInputChallenge)) {
            revert Invalid_Challenge();
        }
    }

    function _base64UrlToBase64(string memory base64Url) internal pure returns (string memory) {
        bytes memory inputBytes = bytes(base64Url);
        bytes memory resultBytes = new bytes(inputBytes.length + 4); // 额外的空间用于可能的padding

        uint256 j = 0;
        for (uint256 i = 0; i < inputBytes.length; i++) {
            if (inputBytes[i] == "-") {
                resultBytes[j] = "+";
            } else if (inputBytes[i] == "_") {
                resultBytes[j] = "/";
            } else {
                resultBytes[j] = inputBytes[i];
            }
            j++;
        }

        uint256 remainder = inputBytes.length % 4;
        if (remainder == 2) {
            resultBytes[j] = "=";
            j++;
            resultBytes[j] = "=";
            j++;
        } else if (remainder == 3) {
            resultBytes[j] = "=";
            j++;
        }

        bytes memory finalResult = new bytes(j);
        for (uint256 i = 0; i < j; i++) {
            finalResult[i] = resultBytes[i];
        }

        return string(finalResult);
    }

    function _parseClientDataJson(string memory clientDataJson)
        internal
        pure
        returns (
            string memory origin,
            string memory authType, // "webauthn.create" vs "webauthn.get"
            string memory challenge
        )
    {
        JSONParserLib.Item memory root = JSONParserLib.parse(clientDataJson);
        JSONParserLib.Item[] memory content = root.children();
        bool originFound;
        bool typeFound;
        bool challengeFound;
        for (uint256 i = 0; i < root.size(); i++) {
            string memory decodedKey = JSONParserLib.decodeString(content[i].key());
            if (decodedKey.eq("origin")) {
                origin = JSONParserLib.decodeString(content[i].value());
                originFound = true;
            } else if (decodedKey.eq("type")) {
                authType = JSONParserLib.decodeString(content[i].value());
                typeFound = true;
            } else if (decodedKey.eq("challenge")) {
                challenge = JSONParserLib.decodeString(content[i].value());
                challengeFound = true;
            }

            if (originFound && typeFound && challengeFound) {
                break;
            }
        }

        if (!originFound || !typeFound || !challengeFound) {
            revert Invalid_Client_Data();
        }
    }
}