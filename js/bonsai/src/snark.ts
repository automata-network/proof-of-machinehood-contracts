import { AbiCoder, ParamType, BytesLike, hexlify } from 'ethers';

const encoder = AbiCoder.defaultAbiCoder();

export type SnarkObject = {
    a: Array<FakeBytesArray>,
    b: Array<Array<FakeBytesArray>>,
    c: Array<FakeBytesArray>
}

// technically they are being passed as an Array of numbers
// those array of numbers are really just bytes array
type FakeBytesArray = Array<number>;

export function serializeSnarkProof(output: SnarkObject): string {
    let serialized = {
        a: convertToUint8Array(output.a),
        b: [convertToUint8Array(output.b[0]), convertToUint8Array(output.b[1])],
        c: convertToUint8Array(output.c)
    };
    // https://github.com/risc0/risc0-ethereum/blob/80e57858780994b9a9361e792e69dd64ebd206d3/contracts/src/groth16/RiscZeroGroth16Verifier.sol#L76-L81
    return encoder.encode([ParamType.from({
        type: 'tuple',
        name: 'Seal',
        components: [
            { type: 'uint256[2]', name: 'a' },
            { type: 'uint256[2][2]', name: 'b' },
            { type: 'uint256[2]', name: 'c' }
        ]
    })], [serialized]);
}

function convertToUint8Array(arr: Array<FakeBytesArray>): Array<BytesLike> {
    let ret = new Array<BytesLike>(arr.length);

    for (let i = 0; i < arr.length; i++) {
        ret[i] = hexlify(Uint8Array.from(arr[i]));
    }

    return ret;
}