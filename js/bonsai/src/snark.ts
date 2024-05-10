import { AbiCoder, ParamType, BytesLike } from 'ethers';
import { convertArrToHex, FakeBytesArray } from './utils';

const encoder = AbiCoder.defaultAbiCoder();

export type SnarkObject = {
    a: Array<FakeBytesArray>,
    b: Array<Array<FakeBytesArray>>,
    c: Array<FakeBytesArray>
}

export function abiEncodeSnarkProof(output: SnarkObject): BytesLike {
    let serialized = {
        a: convertArrToHex(output.a),
        b: [convertArrToHex(output.b[0]), convertArrToHex(output.b[1])],
        c: convertArrToHex(output.c)
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