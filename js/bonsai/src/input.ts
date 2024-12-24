import { AbiCoder, BytesLike } from 'ethers';

const encoder = AbiCoder.defaultAbiCoder();

export function serializeDer(der: Array<BytesLike>): string {
    if (der.length < 2) {
        throw new Error("X509 chain should at least consists of 2 certificates");
    }
    return encoder.encode(['bytes[]'], [der]);
}