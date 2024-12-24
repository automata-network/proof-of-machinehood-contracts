import { BytesLike, hexlify } from 'ethers';

// technically they are being passed as an Array of numbers
// those array of numbers are really just bytes array
export type FakeBytesArray = Array<number>;

export function convertArrToHex(arr: Array<FakeBytesArray>): Array<BytesLike> {
    let ret = new Array<BytesLike>(arr.length);

    for (let i = 0; i < arr.length; i++) {
        ret[i] = hexlify(Uint8Array.from(arr[i]));
    }

    return ret;
}