// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./interfaces/IDerParser.sol";
import "./Asn1Decode.sol";
import "./X509DateUtils.sol";
import "./BytesUtils.sol";

contract DerParser is IDerParser {
    using Asn1Decode for bytes;
    using NodePtr for uint256;

    function parseValidityAndAltSubjectName(bytes memory der, bool parseAltSubjectName)
        public
        pure
        returns (uint256 notBefore, uint256 notAfter, bytes memory subjectAltName)
    {
        uint256 ptr = der.root();

        ptr = der.firstChildOf(ptr);
        ptr = der.nextSiblingOf(ptr);
        ptr = der.nextSiblingOf(ptr);
        ptr = der.nextSiblingOf(ptr);
        ptr = der.nextSiblingOf(ptr);

        // Parse Validity
        uint256 notBeforePtr = der.firstChildOf(ptr);
        uint256 notAfterPtr = der.nextSiblingOf(notBeforePtr);
        bytes1 notBeforeTag = der[notBeforePtr.ixs()];
        bytes1 notAfterTag = der[notAfterPtr.ixs()];
        require(notBeforeTag == 0x17 || notBeforeTag == 0x18, "Not UTCTime or GeneralizedTime");
        require(notAfterTag == 0x17 || notAfterTag == 0x18, "Not UTCTime or GeneralizedTime");
        notBefore = uint40(X509DateUtils.toTimestamp(der.bytesAt(notBeforePtr)));
        notAfter = uint40(X509DateUtils.toTimestamp(der.bytesAt(notAfterPtr)));

        //Parse subjectAltName
        if (parseAltSubjectName) {
            ptr = der.nextSiblingOf(ptr);
            ptr = der.nextSiblingOf(ptr);
            ptr = der.nextSiblingOf(ptr);
            require(der[ptr.ixs()] == 0xA3, "Not extensions");
            ptr = der.firstChildOf(ptr);
            ptr = der.firstChildOf(ptr);

            while (ptr != 0) {
                uint256 objectIdentifierPtr = der.firstChildOf(ptr);
                require(der[objectIdentifierPtr.ixs()] == 0x06, "Not Object Identifier");
                if (BytesUtils.compareBytes(der.bytesAt(objectIdentifierPtr), hex"551D11")) {
                    // 2.5.29.17
                    uint256 internalPtr = der.nextSiblingOf(objectIdentifierPtr);
                    uint256 subAltNamePtr = der.rootOfOctetStringAt(internalPtr);
                    subjectAltName = der.bytesAt(subAltNamePtr);
                    break;
                }

                // Last part of the extensions
                if (ptr.ixl() < der.length - 1) {
                    ptr = der.nextSiblingOf(ptr);
                } else {
                    ptr = 0; // exit
                }
            }
        }
    }
}
