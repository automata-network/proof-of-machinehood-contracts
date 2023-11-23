// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "./BytesUtils.sol";

// Library for parsing certInfo, which is a part of Windows TPM attestation
// The spec is defined in the 10.12.8 section of the document: https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf

library CertInfoParser {
    struct QualifiedSigner {
        uint16 size;
        bytes name;
    }

    struct ExtraData {
        uint16 size;
        bytes20 data;
    }

    struct CertInfo {
        bytes raw;
        bytes magic; // TPM_GENERATED, the indication that this structure was created by a TPM (always TPM_GENERATED_VALUE)
        bytes2 certInfoType; // TPMI_ST_ATTEST, type of the attestation structure
        QualifiedSigner qualifiedSigner; // TPM2B_NAME, qualified Name of the signing key
        ExtraData extraData; // TPM2B_DATA, external information supplied by caller
        bytes8 clock;
        bytes4 resetCount;
        bytes4 restartCount;
        bytes1 safe;
        bytes8 firmwareVersion; // TPM-vendor-specific value identifying the version number of the firmware
        bytes attestedField; // The type-specific attestation information
    }

    function parseCertInfo(bytes memory input) internal pure returns (CertInfo memory certInfo) {
        certInfo.raw = input;
        // certInfo.magic = input[0:4];
        certInfo.magic = BytesUtils.substring(input, 0, 4);
        require(bytes4(certInfo.magic) == 0xff544347, "Invalid magic in certInfo");
        // certInfo.certInfoType = bytes2(input[4:6]);
        certInfo.certInfoType = bytes2(BytesUtils.substring(input, 4, 2));
        require(bytes2(certInfo.certInfoType) == 0x8017, "Invalid type in certInfo");
        uint256 offset = 6;
        require(input.length >= offset + 2, "Invalid qualified signer");
        // certInfo.qualifiedSigner.size = uint16(bytes2(input[offset:offset + 2]));
        certInfo.qualifiedSigner.size = uint16(bytes2(BytesUtils.substring(input, offset, 2)));
        offset += 2;
        require(input.length >= offset + certInfo.qualifiedSigner.size, "Invalid qualified signer");
        // certInfo.qualifiedSigner.name = input[offset:offset + certInfo.qualifiedSigner.size];
        certInfo.qualifiedSigner.name = BytesUtils.substring(input, offset, certInfo.qualifiedSigner.size);
        offset += certInfo.qualifiedSigner.size;

        require(input.length >= offset + 2, "Invalid extra data");
        // certInfo.extraData.size = uint16(bytes2(input[offset:offset + 2]));
        certInfo.extraData.size = uint16(bytes2(BytesUtils.substring(input, offset, 2)));
        require(certInfo.extraData.size == 20, "Invalid extra data size");
        offset += 2;
        // certInfo.extraData.data = bytes20(input[offset:offset + certInfo.extraData.size]);
        certInfo.extraData.data = bytes20(BytesUtils.substring(input, offset, certInfo.extraData.size));
        offset += certInfo.extraData.size;

        // certInfo.clock = bytes8(input[offset:offset + 8]);
        certInfo.clock = bytes8(BytesUtils.substring(input, offset, 8));
        offset += 8;

        // certInfo.resetCount = bytes4(input[offset:offset + 4]);
        certInfo.resetCount = bytes4(BytesUtils.substring(input, offset, 4));
        offset += 4;

        // certInfo.restartCount = bytes4(input[offset:offset + 4]);
        certInfo.resetCount = bytes4(BytesUtils.substring(input, offset, 4));
        offset += 4;

        // certInfo.safe = bytes1(input[offset]);
        certInfo.resetCount = bytes4(BytesUtils.substring(input, offset, 1));
        offset += 1;

        // certInfo.firmwareVersion = bytes8(input[offset:offset + 8]);
        certInfo.resetCount = bytes4(BytesUtils.substring(input, offset, 8));
        offset += 8;

        // certInfo.attestedField = input[offset:];
        certInfo.resetCount = bytes4(BytesUtils.substring(input, offset, input.length - offset));
    }

    function parseExtraData(bytes memory input) internal pure returns (bytes20 extraData) {
        CertInfo memory certInfo = parseCertInfo(input);
        extraData = certInfo.extraData.data;
    }
}
