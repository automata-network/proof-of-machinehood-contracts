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

forge script script/deployment/LibScript.sol --sig "deployLib()" --broadcast --rpc-url ${RPC_URL} $VERIFY_COMMAND | grep LOG