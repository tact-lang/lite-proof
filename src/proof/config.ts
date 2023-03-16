import { Dictionary } from "ton-core";
import { Cell } from "ton-core";
import { Slice } from "ton-core";
import { DictionaryValue } from "ton-core";

function readPublicKey(slice: Slice) {
    // 8e81278a
    if (slice.loadUint(32) !== 0x8e81278a) {
        throw Error('Invalid config');
    }
    return slice.loadBuffer(32);
}

export type ValidatorDescriptor = {
    publicKey: Buffer,
    weight: bigint,
    adnlAddress: Buffer | null
}
const ValidatorDescriptorValue: DictionaryValue<ValidatorDescriptor> = {
    serialize(src, builder) {
        if (src.adnlAddress) {
            builder.storeUint(0x73, 8);
            builder.storeUint(0x8e81278a, 32);
            builder.storeBuffer(src.publicKey);
            builder.storeUint(src.weight, 64);
            builder.storeBuffer(src.adnlAddress);
        } else {
            builder.storeUint(0x53, 8);
            builder.storeUint(0x8e81278a, 32);
            builder.storeBuffer(src.publicKey);
            builder.storeUint(src.weight, 64);
        }
    },
    parse(slice) {
        let header = slice.loadUint(8);
        if (header === 0x53) {
            return {
                publicKey: readPublicKey(slice),
                weight: slice.loadUintBig(64),
                adnlAddress: null
            };
        } else if (header === 0x73) {
            return {
                publicKey: readPublicKey(slice),
                weight: slice.loadUintBig(64),
                adnlAddress: slice.loadBuffer(32)
            };
        } else {
            throw Error('Invalid config');
        }
    }
}

export function parseValidatorSet(slice: Slice) {
    let header = slice.loadUint(8);
    if (header === 0x11) {
        let timeSince = slice.loadUint(32);
        let timeUntil = slice.loadUint(32);
        let total = slice.loadUint(16);
        let main = slice.loadUint(16);
        let list = slice.loadDictDirect(Dictionary.Keys.Int(16), ValidatorDescriptorValue);
        return {
            timeSince,
            timeUntil,
            total,
            main,
            totalWeight: null,
            list
        };
    } else if (header === 0x12) {
        let timeSince = slice.loadUint(32);
        let timeUntil = slice.loadUint(32);
        let total = slice.loadUint(16);
        let main = slice.loadUint(16);
        let totalWeight = slice.loadUintBig(64);
        let list = slice.loadDict(Dictionary.Keys.Int(16), ValidatorDescriptorValue)
        return {
            timeSince,
            timeUntil,
            total,
            main,
            totalWeight,
            list
        };
    } else {
        throw Error('Invalid config');
    }
}

export function configParse28(cell: Cell | null | undefined) {
    if (!cell) {
        throw new Error('Invalid config');
    }
    let slice = cell.beginParse();
    let magic = slice.loadUint(8);
    if (magic === 0xc1) {
        let masterCatchainLifetime = slice.loadUint(32);
        let shardCatchainLifetime = slice.loadUint(32);
        let shardValidatorsLifetime = slice.loadUint(32);
        let shardValidatorsCount = slice.loadUint(32);
        return {
            masterCatchainLifetime,
            shardCatchainLifetime,
            shardValidatorsLifetime,
            shardValidatorsCount
        };
    }
    if (magic === 0xc2) {
        let flags = slice.loadUint(7);
        let suffleMasterValidators = slice.loadBit();
        let masterCatchainLifetime = slice.loadUint(32);
        let shardCatchainLifetime = slice.loadUint(32);
        let shardValidatorsLifetime = slice.loadUint(32);
        let shardValidatorsCount = slice.loadUint(32);
        return {
            flags,
            suffleMasterValidators,
            masterCatchainLifetime,
            shardCatchainLifetime,
            shardValidatorsLifetime,
            shardValidatorsCount
        }
    }
    throw new Error('Invalid config');
}