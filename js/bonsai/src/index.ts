import * as input from './input';
import * as snark from './snark';
import * as server from './server';
import env from 'dotenv';
import { BytesLike } from 'ethers';
import { convertArrToHex } from './utils';

env.config();
const sleepIntervalInSeconds = 15 || process.env.SLEEP_INTERVAL;

export const X509_VERIFIER_IMAGE_ID = 'cc5501e5a9e523737c67ad48e7ac8a2027a9b612f365a22893f3dfa34c0e285d';

export type Output = {
    journal: BytesLike,
    post_state_digest: BytesLike,
    seal: BytesLike
}

export async function generateSnarkProofFromDerChain(der: Array<string>): Promise<Output> {
    // Step 0: Check existence of the ImageId
    const imageIdResponse = await server.checkStatus(server.SessionType.ImageId, X509_VERIFIER_IMAGE_ID);
    if (imageIdResponse.status !== 'EXISTS') {
        throw new Error("The ELF binary for the provided ImageID has not been uploaded");
    }

    // Step 1: Serialize the input
    const serializedInput = await input.serializeDer(der);

    // Step 2: Create a Prove session
    const proveUuid = await server.createProofSession(X509_VERIFIER_IMAGE_ID, "", serializedInput);

    // Step 3: Wait until a Prove session becomes successful
    let proveResponse = await server.checkStatus(server.SessionType.Prove, proveUuid);
    while (proveResponse.status === 'RUNNING') {
        // calls /check status every 15 seconds (default)
        setTimeout(
            async() => {
                proveResponse = await server.checkStatus(
                    server.SessionType.Prove,
                    proveUuid
                );
            }, 
            sleepIntervalInSeconds * 1000
        );
    }
    if (proveResponse.status !== 'SUCCEEDED') {
        throw new Error("Failed to generate STARK proof");
    }

    // Step 4: Convert STARK to SNARK proof
    const snarkUuid = await server.createSnarkSession(proveUuid);
    
    // Step 5: Wait until a SNARK session becomes successful
    let snarkResponse = await server.checkStatus(server.SessionType.Snark, snarkUuid);
    while (snarkResponse.status === 'RUNNING') {
        // calls /check status every 15 seconds (default)
        setTimeout(
            async() => {
                snarkResponse = await server.checkStatus(
                    server.SessionType.Snark,
                    snarkUuid
                );
            }, 
            sleepIntervalInSeconds * 1000
        );
    }

    // Step 6: Serialize the SNARK proofs to seal bytes
    const snarkObj = snarkResponse.output.snark;
    const seal = snark.abiEncodeSnarkProof(snarkObj);
    return {
        journal: convertArrToHex([snarkObj.output.journal])[0],
        post_state_digest: convertArrToHex([snarkObj.output.post_state_digest])[0],
        seal: seal
    }
}

export * from './input';
export * from './snark';
export * from './server';