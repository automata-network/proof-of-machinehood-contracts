// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0;

interface IDerParser {
    function parseValidityAndAltSubjectName(bytes memory der, bool parseAltSubjectName)
        external
        pure
        returns (uint256 notBefore, uint256 notAfter, bytes memory subjectAltName);
}
