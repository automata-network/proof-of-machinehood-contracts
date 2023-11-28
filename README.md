# Proof of Machinehood Contracts

## What is Proof of Machinehood(PoM)
Proof of Machinehood(PoM) is a verifiable attestation that proves ownership of a specific device. This repository contains Solidity libraries designed for integration with third-party smart contracts. These libraries enable on-chain verification of PoM attestations, ensuring secure and reliable confirmation of device ownership.

## How to Get the PoM Attestation
The PoM attestation is a cryptographically-signed statement provided by users' devices. The format and content of this attestation can vary depending on the device type. This includes [SafetyNet Attestations](https://developer.android.com/privacy-and-security/safetynet/attestation) for Android phones, [TPM Key Attestations](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/tpm-key-attestation) for Windows devices, and [App Attestations](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server) for Apple devices.

In this project, we utilize [Web Authentication](https://www.w3.org/TR/webauthn/#sec-authenticator-data) to acquire attestations from different devices. This approach allows us to gather attestations in a standardized manner, without delving into the specifics of each device type. Using Web Authentication to create credentials yields a signed data object known as the "attestation statement." This statement includes information about the credential and the device that created it. We use the attestation statement to substantiate the PoM of a device.

Experience it yourself with the [Proof of Machinehood Demo](https://pom.ata.network/) and attest your own device!

## Supported Devices
Currently, we support the following devices:
- Android Device
- Windows Device
- Yubikey

### Verification of Attestation from Android Device
```solidity
struct AttStmt {
    ISigVerifyLib.Algorithm alg;
    string jwtHeader;
    string jwtPayload;
    string jwtSignature;
    ISigVerifyLib.Certificate[] x5c;
}
```
Below is the attestation statement from an Android device, verified by this library, along with a detailed explanation of each field:
- `alg`: The algorithm used to generate the signature(`jwtSignature`) for the JWT (JSON Web Token).
- `jwtHeader`: The header of the JWT obtained from Google's SafetyNet Service. This field contains a certificate chain that can be used to verify the identity of the device.
- `jwtPayload`: The payload of the JWT from Google's SafetyNet Service. It includes fields such as `ctsProfileMatch` and `basicIntegrity`, which help in checking the device's integrity.
- `jwtSignature`: The signature part of the JWT from Google's SafetyNet Service, which is signed using the first certificate in the x5c array.
- `x5c`: The certificate chain included in the `jwtHeader`. This field is added to simplify the on-chain implementation process. Technically, it's possible to extract the certificate chain directly from the `jwtHeader`.

For more detailed information, please refer to the [complete verification procedure](https://www.w3.org/TR/webauthn-2/#sctn-android-safetynet-attestation).

### Verification of Attestation from Windows Device
```solidity
struct AttStmt {
    ISigVerifyLib.Algorithm alg;
    bytes sig;
    ISigVerifyLib.Certificate[] x5c;
    bytes certInfo;
}
```
Below is the attestation statement from a Windows device, verified by this library, along with a detailed explanation of each field:
- `alg`: The algorithm used to generate the signature `sig`.
- `sig`: The signature created using the first certificate in `x5c`. It provides cryptographic proof of various properties of the device and the credential.
- `x5c`: The certificate chain that verifies the identity of the device.
- `certInfo`: This is the data that is signed and represents a [complex structure](https://github.com/automata-network/machinehood-contracts/blob/d3fd0a81f66d48706da445001142bef93125e3b2/src/utils/CertInfoParser.sol#L17-L29) defined by Microsoft.

For more comprehensive information, please refer to the [complete verification procedure](https://www.w3.org/TR/webauthn-2/#sctn-tpm-attestation).

### Verification of Attestation from Yubikey
```solidity
struct AttStmt {
    ISigVerifyLib.Algorithm alg;
    bytes signature;
    ISigVerifyLib.Certificate[] x5c;
}
```
Below is the attestation statement from a Yubikey, verified by this library, along with a detailed explanation of each field:
- `alg`: The algorithm used to generate the signature `sig`.
- `sig`: The signature created using the first certificate in `x5c`. It provides cryptographic proof of specific properties of the device and the credential.
- `x5c`: The certificate chain that verifies the identity of the device.

For more comprehensive information, please refer to the [complete verification procedure](https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation).

## Will Submitting Attestation On-Chain Reveal My Privacy?
**No, your privacy is well protected.** The attestation only proves that it is generated by a specific type of device and does not include any identifiable information about the device itself. Therefore, even though the verification is completed on-chain, this process will not compromise your privacy.

## Does the Attestation Prove That Users Owns the Device?
**No, the attestation itself cannot conclusively prove that users own the device.** It only confirms that the user had control over a specific device at the time of attestation generation. This is because generating the attestation requires completing device-specific authentication, such as entering a PIN code or using a fingerprint. However, it doesn't guarantee continued ownership or control of the device thereafter.

**To be precise, attestation can only verify device ownership within a specific time frame.** For instance, when a user generates an attestation, we can be certain they owned the device at that moment. However, the certainty of ownership naturally decreases over time. As an illustrative example, this might hypothetically drop to 98% after 5 minutes and further to 80% after a day, though these specific percentages are not actual measurements but rather are used to demonstrate the concept. Therefore, when integrating the PoM library, you should consider how to interpret and utilize the attestation data based on the specific needs and context of your application.

## For Developers: Integrate with Proof of Machinehood
Solidity developers can simply import `AttestationVerificationBase.sol` to their contract regardless of the device type, since they all implement the `verifyAttStmt()` method. See example below:

```solidity

import {AttestationVerificationBase} from "@automata-network/machinehood-contracts/AttestationVerificationBase.sol";

contract ExamplePOM {

    AttestationVerificationBase android;
    AttestationVerificationBase windows;
    // ...

    constructor(address _android, address _windows) {
        android = AttestationVerificationBase(_android);
        windows = AttestationVerificationBase(_windows);
    }

    /// @dev it only cares about Android, cuz Google rocks!
    function verifyAndroidAttestation(
        bool isAndroid,
        bytes calldata challenge,
        bytes calldata attStmt,
        bytes calldata authData,
        bytes calldata clientData
    ) external returns (bool verified) {
        // ...
        
        if (isAndroid) {
            (verified, ) = android.verifyAttStmt(
                challenge,
                attStmt,
                authData,
                clientData
            );
        }
    }

}

```

# #BUIDL on POM 🛠️

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```
