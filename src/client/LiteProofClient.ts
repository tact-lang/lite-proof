import { LiteClient } from "@tact-lang/lite-client";
import { Cell } from "ton-core";
import { verifyProofLink } from "../proof/verify";
import { AsyncLock } from "../utils/lock";
import { Maybe } from "../utils/Maybe";
import { createMemoryStorage, ProofStorage } from "./ProofStorage";

export type LiteProofEndpoint = {
    host: string;
    publicKey: string;
}

export type BlockId = {
    seqno: number;
    rootHash: Buffer;
    fileHash: Buffer;
};

export class LiteProofClient {

    #storage: ProofStorage;
    #liteClient: LiteClient;
    #init: BlockId;
    #currentBlock: BlockId | null = null;
    #currentKeyBlock: BlockId | null = null;
    #lock = new AsyncLock();

    constructor(args: {
        endpoints: LiteProofEndpoint[],
        init: BlockId,
        storage?: Maybe<ProofStorage>
    }) {

        // Init block
        this.#init = args.init;

        // Create storage
        if (args.storage) {
            this.#storage = args.storage;
        } else {
            this.#storage = createMemoryStorage();
        }

        // Create lite client
        this.#liteClient = LiteClient.create(args.endpoints);
    }

    async updateLastBlock() {
        await this.#lock.inLock(async () => {

            // Load last block
            let lastBlock: BlockId;
            if (this.#currentKeyBlock) {
                lastBlock = this.#currentKeyBlock;
            } else {
                let lastBlockStored = await this.#storage.loadProof('last_block');
                if (lastBlockStored) {
                    let sc = (Cell.fromBase64(lastBlockStored)).beginParse();
                    let s = sc.loadUint(32);
                    let r = sc.loadBuffer(32);
                    let f = sc.loadBuffer(32);
                    lastBlock = { seqno: s, rootHash: r, fileHash: f };
                } else {
                    lastBlock = this.#init;
                }
            }

            // Load proof
            while (true) {
                console.warn('Loading block proof...');
                let res = await this.#liteClient.getBlockProof({
                    kind: 'liteServer.getBlockProof',
                    mode: 0,
                    knownBlock: {
                        kind: 'tonNode.blockIdExt',
                        workchain: -1,
                        shard: '-9223372036854775808',
                        seqno: lastBlock.seqno,
                        rootHash: lastBlock.rootHash,
                        fileHash: lastBlock.fileHash
                    },
                    targetBlock: null
                });

                // Check proofs
                for (let i = 0; i < res.steps.length; i++) {

                    // Check link
                    let link = res.steps[i];
                    if (!link.from.fileHash.equals(lastBlock.fileHash) || link.from.seqno !== lastBlock.seqno) {
                        throw new Error('Invalid link');
                    }
                    if (link.kind !== 'liteServer.blockLinkForward') {
                        throw new Error('Invalid link');
                    }

                    // Verify
                    verifyProofLink({
                        toKeyBlock: link.toKeyBlock,
                        from: {
                            workchain: -1,
                            shard: -9223372036854775808n,
                            seqno: link.from.seqno,
                            rootHash: link.from.rootHash,
                            fileHash: link.from.fileHash
                        },
                        to: {
                            workchain: -1,
                            shard: -9223372036854775808n,
                            seqno: link.to.seqno,
                            rootHash: link.to.rootHash,
                            fileHash: link.to.fileHash
                        },
                        destProof: link.destProof,
                        configProof: link.configProof,
                        signatures: link.signatures
                    });


                    // Update key block
                    if (link.toKeyBlock) {
                        this.#currentKeyBlock = {
                            seqno: link.to.seqno,
                            rootHash: link.to.rootHash,
                            fileHash: link.to.fileHash
                        };
                        lastBlock = {
                            seqno: link.to.seqno,
                            rootHash: link.to.rootHash,
                            fileHash: link.to.fileHash
                        }
                    }

                    // Save block
                    this.#currentBlock = {
                        seqno: link.to.seqno,
                        rootHash: link.to.rootHash,
                        fileHash: link.to.fileHash
                    }
                }

                if (res.complete) {
                    break;
                }
            }
        });
    }
}