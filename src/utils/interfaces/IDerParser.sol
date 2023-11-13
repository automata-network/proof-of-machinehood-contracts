//SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

interface IDerParser {
    function parseValidityAndAltSubjectName(bytes memory der, bool parseAltSubjectName)
        external
        pure
        returns (uint256 notBefore, uint256 notAfter, bytes memory subjectAltName);
}
