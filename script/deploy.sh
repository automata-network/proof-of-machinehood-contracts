#!/bin/bash

source .env

VERIFY_COMMAND=""

for (( i=1; i<=$#; i++ )); do
    if [ "${!i}" = "--verify" ]
    then
        VERIFY_COMMAND="--verify --verifier blockscout --verifier-url ${VERIFIER_URL}"
        continue
    fi
done

forge script script/Deploy.sol --sig "deployAndroidSafetyNet()" --broadcast -vvvv --rpc-url ${RPC_URL} $VERIFY_COMMAND
forge script script/Deploy.sol --sig "deployWindowsTPM()" --broadcast -vvvv --rpc-url ${RPC_URL} $VERIFY_COMMAND
forge script script/Deploy.sol --sig "deployYubikey()" --broadcast -vvvv --rpc-url ${RPC_URL} $VERIFY_COMMAND