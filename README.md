# Machinehood Integration Contracts

This repo contains Solidity libraries that can be integrated with third-party smart contracts to perform on-chain verification on machinehood attestations. The devices that we currently support are:

- Android
- Windows
- Yubikey

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
