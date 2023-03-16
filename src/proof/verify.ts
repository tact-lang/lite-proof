import { Dictionary } from "ton-core";
import { Cell, exoticMerkleProof, loadShardIdent } from "ton-core";
import { sha256_sync } from "ton-crypto";
import { ed25519 } from '@noble/curves/ed25519';
import { configParse28, parseValidatorSet, ValidatorDescriptor } from "./config";
import { ValidatorPRNG } from "./validatorPRNG";

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
    let vsProofHash = exoticMerkleProof(vsRootCell.bits, vsRootCell.refs).proofHash;
    assert(vsProofHash.equals(link.from.rootHash), "{ proof_hash == link.from.rootHash }");
    let blkSrc = checkBlockHeader(vsRootCell, link.from);
    if (!blkSrc.extras || !blkSrc.extras.config) {
        throw new Error("Source block must have config");
    }
    let configCell = blkSrc.extras.config;

    // To proof
    let vdRootCell = Cell.fromBoc(destProof)[0];
    let vdProofHash = exoticMerkleProof(vdRootCell.bits, vdRootCell.refs).proofHash;
    assert(vdProofHash.equals(link.to.rootHash), "{ proof_hash == link.to.rootHash }");
    let blk = checkBlockHeader(vdRootCell, link.to);
    if (blk.info.keyBlock !== link.toKeyBlock) {
        throw new Error("Proof link must have a key block as destination");
    }

    // Parse config
    let dict = Dictionary.loadDirect(Dictionary.Keys.Int(32), Dictionary.Values.Cell(), configCell);
    let catchain = configParse28(dict.get(28));
    let validatorsDict = parseValidatorSet(dict.get(34)!.beginParse());

    // Compute validator nodes
    // https://github.com/ton-blockchain/ton/blob/fc9542f5e223140fcca833c189f77b1a5ae2e184/crypto/block/mc-config.cpp#L1731
    // https://github.com/ton-blockchain/ton/blob/fc9542f5e223140fcca833c189f77b1a5ae2e184/crypto/block/mc-config.cpp#L1843
    let count = Math.min(validatorsDict.main, validatorsDict.total); // Shard?
    assert(validatorsDict.list.size === validatorsDict.total, "{ validators.list.size() == validators.total }");
    let rng = new ValidatorPRNG(-1, 0n, blk.info.genCatchainSeqno, Buffer.alloc(32, 0));
    let validators: ValidatorDescriptor[] = [];
    for (let v of validatorsDict.list) {
        validators[v[0]] = v[1];
    }
    let nodes: ValidatorDescriptor[] = [];
    if (catchain.suffleMasterValidators) {
        let idx = new Array(count);
        for (let i = 0; i < count; i++) {
            let j = rng.nextRanged(i + 1); // number 0 .. i
            assert(j <= i, "{ j <= i }");
            idx[i] = idx[j];
            idx[j] = i;
        }
        for (let i = 0; i < count; i++) {
            let v = validators[idx[i]];
            nodes.push(v);
        }
    } else {
        for (let i = 0; i < count; i++) {
            let v = validators[i];
            nodes.push(v);
        }
    }

    // ValidatorSet hash
    // https://github.com/ton-blockchain/ton/blob/24dc184a2ea67f9c47042b4104bbb4d82289fac1/crypto/block/block.cpp#L2136


    // Check block signatures
    checkBlockSignatures(nodes, link.signatures, link.to);
}

function checkBlockSignatures(nodes: ValidatorDescriptor[], signatures: BlockSignatures, to: BlockIdExt) {

    // Block hash
    let toSign = Buffer.alloc(68);
    toSign.writeUInt32LE(0xc50b6e70, 0); // td::as<td::uint32>(to_sign) = 0xc50b6e70;  // ton.blockId root_cell_hash:int256 file_hash:int256 = ton.BlockId;
    toSign.set(to.rootHash, 4); // memcpy(to_sign + 4, blkid.root_hash.data(), 32);
    toSign.set(to.fileHash, 36); // memcpy(to_sign + 36, blkid.file_hash.data(), 32);

    // Build node map
    let nodeMap = new Map<string, ValidatorDescriptor>();
    let totalWeight: bigint = 0n;
    for (let n of nodes) {
        totalWeight += n.weight;
        nodeMap.set(computeNodeIdShort(n.publicKey).toString('hex'), n);
    }

    // Signatures
    let signedWeight: bigint = 0n;
    let seen = new Set<string>();
    for (let s of signatures.signatures) {
        let k = s.nodeIdShort.toString('hex');
        if (seen.has(k)) {
            throw new Error("Duplicate signature for node");
        }
        seen.add(k);
        let node = nodeMap.get(k);
        if (!node) {
            throw new Error("Signature for unknown node");
        }
        if (!ed25519.verify(s.signature, toSign, node.publicKey)) {
            throw new Error("Invalid signature " + s.signature.toString('hex'));
        }
        signedWeight += node.weight;
    }

    if (3n * signedWeight <= 2n * totalWeight) {
        throw new Error("Too few signatures");
    }
}

// Source: https://github.com/ton-blockchain/ton/blob/e37583e5e6e8cd0aebf5142ef7d8db282f10692b/crypto/block/check-proof.cpp#L487
function computeNodeIdShort(publicKey: Buffer) {
    let m = Buffer.alloc(4);
    m.writeUint32LE(0x4813b4c6, 0)
    return sha256_sync(Buffer.concat([m, publicKey]));
}

function checkBlockHeader(root: Cell, blockId: BlockId) {

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
        throw new Error("Block header contains block id " + id + ", expected " + blockId);
    }

    // Check shard chain
    if (!notMaster !== (shard.workchainId === -1)) {
        throw new Error("Block has invalid notMaster flag in its (Merkelized) header");
    }

    //
    // Pruned references
    //

    block.loadRef(); // value_flow:^ValueFlow
    block.loadRef(); // state_update:^(MERKLE_UPDATE ShardState)

    //
    // Parse extra
    //

    let extras: {
        randomSeed: bigint,
        createdBy: bigint,
        config: Cell | null
    } | null = null;

    let blockExtra = block.loadRef();
    block.endParse();
    if (!blockExtra.isExotic) {
        let es = blockExtra.beginParse();
        es.loadRef(); // block_extra in_msg_descr:^InMsgDescr
        es.loadRef(); // out_msg_descr:^OutMsgDescr
        es.loadRef(); // account_blocks:^ShardAccountBlocks
        if (es.loadUint(32) !== 0x4a33f6fd) {
            throw new Error("BlockExtra header must be equal to 0x4a33f6fd");
        }

        let randomSeed = es.loadUintBig(256);
        let createdBy = es.loadUintBig(256);
        let config: Cell | null = null;

        // Load config
        let mcExtrasCell = es.loadMaybeRef();
        es.endParse();

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