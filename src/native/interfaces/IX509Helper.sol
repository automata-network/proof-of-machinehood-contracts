// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.0;

/// @notice Contract interface used to interact with the X509Helper.sol contract
/// See code: https://github.com/automata-network/automata-on-chain-pccs/blob/main/src/helper/X509Helper.sol

interface IX509Helper {
    /**
     * @title Solidity Structure representing X509 Certificates
     * @notice This is a simplified structure of a DER-decoded X509 Certificate
     */
    struct X509CertObj {
        uint256 serialNumber;
        string issuerCommonName;
        uint256 validityNotBefore;
        uint256 validityNotAfter;
        string subjectCommonName;
        bytes subjectPublicKey;
        // the extension needs to be parsed further
        // this ideally should be done in a contract that serves as an extension to this contract as base
        uint256 extensionPtr;
        // for signature verification in the cert chain
        bytes signature;
        bytes tbs;
    }

    function getTbsAndSig(bytes calldata der) external pure returns (bytes memory tbs, bytes memory sig);

    function getSerialNumber(bytes calldata der) external pure returns (uint256 serialNum);

    function getIssuerCommonName(bytes calldata der) external pure returns (string memory issuerCommonName);

    function certIsNotExpired(bytes calldata der) external view returns (bool isValid);

    function getSubjectCommonName(bytes calldata der) external pure returns (string memory subjectCommonName);

    function getSubjectPublicKey(bytes calldata der) external pure returns (bytes memory pubKey);

    /// x509 Certificates generally contain a sequence of elements in the following order:
    /// 1. tbs
    /// - 1a. version
    /// - 1b. serial number
    /// - 1c. siganture algorithm
    /// - 1d. issuer
    /// - - 1d(a). common name
    /// - - 1d(b). organization name
    /// - - 1d(c). locality name
    /// - - 1d(d). state or province name
    /// - - 1d(e). country name
    /// - 1e. validity
    /// - - 1e(a) notBefore
    /// - - 1e(b) notAfter
    /// - 1f. subject
    /// - - contains the same set of elements as 1d
    /// - 1g. subject public key info
    /// - - 1g(a). algorithm
    /// - - 1g(b). subject public key
    /// - 1h. Extensions
    /// 2. Signature Algorithm
    /// 3. Signature
    /// - 3a. X value
    /// - 3b. Y value
    function parseX509DER(bytes calldata der) external pure returns (X509CertObj memory cert);
}