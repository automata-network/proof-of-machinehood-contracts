import { AbiCoder, BytesLike } from 'ethers';

const encoder = AbiCoder.defaultAbiCoder();

export function serializeDer(der: Array<BytesLike>): string {
    return encoder.encode(['bytes[]'], [der]);
}