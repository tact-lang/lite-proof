export type BlockId = {
    seqno: number,
    workchain: number,
    shard: string,
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
    from: BlockId,
    to: BlockId,
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

    
}