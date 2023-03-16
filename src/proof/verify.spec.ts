import { BlockId, BlockIdExt, BlockSignatures, verifyProofLink } from "./verify";
import proof from './__testdata__/proof.json';
import proof2 from './__testdata__/proof2.json';

describe('verify', () => {
    it('should verify a proof', async () => {

        // Load case
        const from: BlockIdExt = {
            workchain: -1,
            shard: -9223372036854775808n,
            "seqno": proof.from.seqno,
            "rootHash": Buffer.from(proof.from.rootHash, 'base64'),
            "fileHash": Buffer.from(proof.from.fileHash, 'base64')
        };
        const toKeyBlock = true;
        const to: BlockIdExt = {
            workchain: -1,
            shard: -9223372036854775808n,
            "seqno": proof.to.seqno,
            "rootHash": Buffer.from(proof.to.rootHash, 'base64'),
            "fileHash": Buffer.from(proof.to.fileHash, 'base64')
        };
        const destProof = Buffer.from(proof.destProof, 'base64');
        const configProof = Buffer.from(proof.configProof, 'base64');
        const signatures: BlockSignatures = {
            "validatorSetHash": proof.signatures.validatorSetHash,
            "catchainSeqno": proof.signatures.catchainSeqno,
            "signatures": proof.signatures.signatures.map((s) => ({
                nodeIdShort: Buffer.from(s.nodeIdShort, 'base64'),
                signature: Buffer.from(s.signature, 'base64')
            }))
        };

        // Verify
        verifyProofLink({ from, to, toKeyBlock, destProof, configProof, signatures });
    });

    it('should verify a proof2', async () => {

        // Load case
        const from: BlockIdExt = {
            workchain: -1,
            shard: -9223372036854775808n,
            "seqno": proof2.from.seqno,
            "rootHash": Buffer.from(proof2.from.rootHash, 'base64'),
            "fileHash": Buffer.from(proof2.from.fileHash, 'base64')
        };
        const toKeyBlock = true;
        const to: BlockIdExt = {
            workchain: -1,
            shard: -9223372036854775808n,
            "seqno": proof2.to.seqno,
            "rootHash": Buffer.from(proof2.to.rootHash, 'base64'),
            "fileHash": Buffer.from(proof2.to.fileHash, 'base64')
        };
        const destProof = Buffer.from(proof2.destProof, 'base64');
        const configProof = Buffer.from(proof2.configProof, 'base64');
        const signatures: BlockSignatures = {
            "validatorSetHash": proof2.signatures.validatorSetHash,
            "catchainSeqno": proof2.signatures.catchainSeqno,
            "signatures": proof2.signatures.signatures.map((s) => ({
                nodeIdShort: Buffer.from(s.nodeIdShort, 'base64'),
                signature: Buffer.from(s.signature, 'base64')
            }))
        };

        // Verify
        verifyProofLink({ from, to, toKeyBlock, destProof, configProof, signatures });
    });
});