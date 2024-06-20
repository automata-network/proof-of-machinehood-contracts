import * as Input from './input';
import * as Snark from './snark';
import Server, {SessionType} from './server';
import { BytesLike } from 'ethers';
import { convertArrToHex } from './utils';

export const X509_VERIFIER_IMAGE_ID = 'cc5501e5a9e523737c67ad48e7ac8a2027a9b612f365a22893f3dfa34c0e285d';

export type Output = {
    journal: BytesLike,
    seal: BytesLike
}

export async function generateSnarkProofFromDerChain(bonsaiApiKey: string, der: Array<string>): Promise<Output> {
    // Step 0: Instantiate the server
    const server = new Server({
        bonsaiApiKey: bonsaiApiKey
    });

    console.log("step 0");

    // Step 1: Check existence of the ImageId
    const imageIdResponse = await server.checkStatus(SessionType.ImageId, X509_VERIFIER_IMAGE_ID);
    if (imageIdResponse.status !== 204) {
        throw new Error("The ELF binary for the provided ImageID has not been uploaded");
    }

    console.log("step 1");

    // Step 2: Serialize the input
    const serializedInput = await Input.serializeDer(der);

    console.log("step 2");

    // Step 3: Create a Prove session
    const proveUuid = await server.createProofSession(X509_VERIFIER_IMAGE_ID, "", serializedInput.substring(2));

    console.log("step 3");
    console.log("Prove UUID: ", proveUuid);

    // Step 4: Wait until a Prove session becomes successful

    let proveResponse = await server.checkStatus(SessionType.Prove, proveUuid);
    let proveResponseBody = await proveResponse.json();

    while (proveResponseBody.status === 'RUNNING') {
        proveResponse = await server.checkStatus(SessionType.Prove, proveUuid);
        proveResponseBody = await proveResponse.json();
        console.log(proveResponseBody);
    }
    if (proveResponseBody.status !== 'SUCCEEDED') {
        throw new Error("Failed to generate STARK proof");
    }

    console.log("step 4");

    // Step 5: Convert STARK to SNARK proof
    const snarkUuid = await server.createSnarkSession(proveUuid);

    console.log("step 5");
    console.log("Snark UUID: ", snarkUuid);
    
    // Step 6: Wait until a SNARK session becomes successful
    let snarkResponse = await server.checkStatus(
        SessionType.Snark,
        snarkUuid
    );
    let snarkResponseBody = await snarkResponse.json();

    while (snarkResponseBody.status === 'RUNNING') {
        snarkResponse = await server.checkStatus(SessionType.Snark, snarkUuid);
        snarkResponseBody = await snarkResponse.json();
        console.log(snarkResponseBody);
    }
    if (snarkResponseBody.status !== 'SUCCEEDED') {
        throw new Error("Failed to generate STARK proof");
    }

    console.log("step 6");

    // Step 7: Serialize the SNARK proofs to seal bytes
    const snarkObj = snarkResponseBody!.output;
    const seal = Snark.abiEncodeSnarkProof(snarkObj.snark);

    const ret = {
        journal: convertArrToHex([snarkObj.journal])[0],
        seal: seal
    };

    console.log("step 7");
    console.log(ret);

    return ret;
}

export * from './input';
export * from './snark';
export {Server, SessionType};