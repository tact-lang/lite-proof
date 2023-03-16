import { Dictionary } from "ton-core";
import { Cell, exoticMerkleProof, loadShardIdent } from "ton-core";

export type BlockId = {
    seqno: number,
    workchain: number,
    shard: bigint
}

export type BlockIdExt = BlockId & {
    fileHash: Buffer,
    rootHash: Buffer
}

export type BlockSignatures = {
    validatorSetHash: number,
    catchainSeqno: number,
    signatures: {
        nodeIdShort: Buffer,
        signature: Buffer
    }[]
};


// SOURCE: https://github.com/ton-blockchain/ton/blob/e37583e5e6e8cd0aebf5142ef7d8db282f10692b/crypto/block/check-proof.cpp#L318
export function verifyProofLink(link: {
    toKeyBlock: boolean,
    from: BlockIdExt,
    to: BlockIdExt,
    destProof: Buffer,
    configProof: Buffer,
    signatures: BlockSignatures
}) {

    // Preflight checks
    if (link.from.workchain !== -1 || link.to.workchain !== -1) {
        throw new Error("Proof link must have both source and destination blocks in the masterchain");
    }
    if (link.from.seqno === link.to.seqno) {
        throw new Error("Proof link must have different source and destination blocks");
    }
    if (link.from.seqno > link.to.seqno) {
        throw new Error("Proof link must have source block with smaller seqno than destination block");
    }
    if (link.signatures.signatures.length === 0) {
        throw new Error("Proof link must have at least one signature");
    }

    // Rename variables of proofs to match C++ code
    let proof = link.configProof; // https://github.com/ton-blockchain/ton/blob/24dc184a2ea67f9c47042b4104bbb4d82289fac1/lite-client/lite-client-common.cpp#L56
    let destProof = link.destProof;

    // From proof
    let vsRootCell = Cell.fromBoc(proof)[0];
    exoticMerkleProof(vsRootCell.bits, vsRootCell.refs);
    let blkSrc = checkBlockHeader(vsRootCell, link.from);
    if (!blkSrc.extras || !blkSrc.extras.config) {
        throw new Error("Source block must have config");
    }
    let configCell = blkSrc.extras.config;

    // To proof
    let vdRootCell = Cell.fromBoc(destProof)[0];
    exoticMerkleProof(vdRootCell.bits, vdRootCell.refs);
    let blk = checkBlockHeader(vdRootCell, link.to);
    if (blk.info.keyBlock !== link.toKeyBlock) {
        throw new Error("Proof link must have a key block as destination");
    }

    // Parse config
    let dict = Dictionary.loadDirect(Dictionary.Keys.Int(32), Dictionary.Values.Cell(), configCell);
    let catchain = configParse28(dict.get(28));
    console.warn(catchain);
}

export function checkBlockHeader(root: Cell, blockId: BlockId) {

    //
    // Source: https://github.com/ton-blockchain/ton/blob/e37583e5e6e8cd0aebf5142ef7d8db282f10692b/crypto/block/block.tlb#L446
    // Most of the refs are pruned, so we need to load only basic ones
    // 

    let block = root.refs[0].beginParse();
    if (block.loadUint(32) !== 0x11ef55aa) {
        throw new Error("Block header must be equal to 0x11ef55aa");
    }
    let globalId = block.loadInt(32);

    // 
    // Parse info
    // Source: https://github.com/ton-blockchain/ton/blob/e37583e5e6e8cd0aebf5142ef7d8db282f10692b/crypto/block/block.tlb#L422
    //

    let info = block.loadRef().beginParse();
    if (info.loadUint(32) !== 0x9bc7a987) {
        throw new Error("BlockInfo header must be equal to 0x9bc7a987");
    }
    let version = info.loadUint(32);
    let notMaster = info.loadBit();
    let afterMerge = info.loadBit();
    let beforeSplit = info.loadBit();
    let afterSplit = info.loadBit();
    let wantSplit = info.loadBit();
    let wantMerge = info.loadBit();
    let keyBlock = info.loadBit();
    let vertSeqnoIncr = info.loadUint(1);
    let flags = info.loadUint(8); assert(flags <= 1, "{ flags <= 1 }");
    let seqno = info.loadUint(32);
    let vertSeqno = info.loadUint(32); assert(vertSeqno >= vertSeqnoIncr, '{ vert_seq_no >= vert_seqno_incr }');
    let shard = loadShardIdent(info);
    let genTime = info.loadUint(32);
    let startLt = info.loadUintBig(64);
    let endLt = info.loadUintBig(64);
    let genValidatorListHashShort = info.loadUint(32);
    let genCatchainSeqno = info.loadUint(32);
    let minRefMcSeqno = info.loadUint(32);
    let prevKeyBlockSeqno = info.loadUint(32);

    // Check block id
    let id: BlockId = {
        seqno,
        workchain: shard.workchainId,
        shard: shard.shardPrefix,
    }
    if (id.workchain !== blockId.workchain || id.seqno !== blockId.seqno /* || id.shard !== blockId.shard */) {
        console.warn(id);
        console.warn(blockId);
        throw new Error("Block header contains block id " + id + ", expected " + blockId);
    }

    // Check shard chain
    if (!notMaster !== (shard.workchainId === -1)) {
        throw new Error("Block has invalid notMaster flag in its (Merkelized) header");
    }

    //
    // Parse extra
    //
    block.loadRef(); // value_flow:^ValueFlow
    block.loadRef(); // state_update:^(MERKLE_UPDATE ShardState)
    let extrasCell = block.loadRef();
    let extras: {
        randomSeed: bigint,
        createdBy: bigint,
        config: Cell | null
    } | null = null;
    if (!extrasCell.isExotic) {
        let es = extrasCell.beginParse();
        es.loadRef(); // block_extra in_msg_descr:^InMsgDescr
        es.loadRef(); // out_msg_descr:^OutMsgDescr
        es.loadRef(); // account_blocks:^ShardAccountBlocks

        let randomSeed = es.loadUintBig(256);
        let createdBy = es.loadUintBig(256);
        let config: Cell | null = null;

        // Load config
        let mcExtrasCell = es.loadMaybeRef();
        if (mcExtrasCell) {
            let mxExtra = mcExtrasCell.beginParse();
            if (mxExtra.loadUint(16) !== 0xcca5) {
                throw new Error("McBlockExtra header must be equal to 0xcca5");
            }
            let keyBlock = mxExtra.loadBit();
            if (keyBlock) {

                mxExtra.loadMaybeRef(); // _ (HashmapE 32 ^(BinTree ShardDescr)) = ShardHashes;
                mxExtra.loadMaybeRef(); // _ (HashmapAugE 96 ShardFeeCreated ShardFeeCreated) = ShardFees;

                // ^[ prev_blk_signatures:(HashmapE 16 CryptoSignaturePair)
                //     recover_create_msg:(Maybe ^InMsg)
                //     mint_msg:(Maybe ^InMsg) ]
                mxExtra.loadRef();

                // config:key_block?ConfigParams
                config = mxExtra.loadRef();
            }
        }

        extras = {
            randomSeed,
            createdBy,
            config
        } as const
    }

    return {
        globalId,
        info: {
            version,
            notMaster,
            afterMerge,
            beforeSplit,
            afterSplit,
            wantSplit,
            wantMerge,
            keyBlock,
            vertSeqnoIncr,
            flags,
            seqno,
            vertSeqno,
            shard,
            genTime,
            startLt,
            endLt,
            genValidatorListHashShort,
            genCatchainSeqno,
            minRefMcSeqno,
            prevKeyBlockSeqno
        },
        extras
    }
}

function assert(condition: boolean, message: string) {
    if (!condition) {
        throw new Error(message);
    }
}

function configParse28(cell: Cell | null | undefined) {
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