import { sha512_sync } from "ton-crypto";

export class ValidatorPRNG {

    // Validator set desc
    // unsigned char seed[32];  // seed for validator set computation, set to zero if none
    // td::uint64 shard;
    // td::int32 workchain;
    // td::uint32 cc_seqno;
    seed: Buffer;
    shard: bigint;
    workchain: number;
    ccSeqno: number;

    // Internal set
    #hash: Buffer = Buffer.alloc(8 * 8);
    #pos = 0;
    #limit = 0;

    constructor(workchain: number, shard: bigint, ccSeqno: number, seed: Buffer) {
        this.ccSeqno = ccSeqno;
        this.shard = shard;
        this.workchain = workchain;
        this.seed = seed
    }

    nextUlong() {
        if (this.#pos < this.#limit) {
            return this.#hash.readBigUInt64BE(this.#pos++ * 8);
        }

        // data.hash_to(hash);
        this.#rebuildHash();
        this.#increaseSeed();
        this.#pos = 1;
        this.#limit = 8;
        return this.#hash.readBigUInt64BE(0);
    }

    nextRanged(range:number) {
        let y = this.nextUlong();
        return Number((BigInt(range) * y) >> 64n);
    }

    #increaseSeed() {
        for (let i = 31; i >= 0 && !++(this.seed[i]); --i) {
        }
    }

    #rebuildHash() {
        let toHash = Buffer.alloc(32 + 8 + 4 + 4);
        this.seed.copy(toHash, 0);
        toHash.writeBigUInt64BE(this.shard, 32);
        toHash.writeInt32BE(this.workchain, 32 + 8);
        toHash.writeInt32BE(this.ccSeqno, 32 + 8 + 4);
        this.#hash = sha512_sync(toHash);
    }
}