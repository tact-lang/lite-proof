import { LiteProofClient } from "./LiteProofClient";
jest.setTimeout(120000);

describe('LiteProofClient', () => {
    it('should be able to create a LiteProofClient', async () => {

        // Create client
        let client = new LiteProofClient({
            endpoints: [{
                host: 'tcp://5.9.10.47:19949',
                publicKey: 'n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk='
            }, {
                host: 'tcp://5.9.10.47:19949',
                publicKey: 'n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk='
            }],
            init: {
                seqno: 27747086,
                rootHash: Buffer.from('YRkrcmZMvLBvjanwKCyL3w4oceGPtFfgx8ym1QKCK/4=', 'base64'),
                fileHash: Buffer.from('N42xzPnJjDlE3hxPXOb+pNzXomgRtpX5AZzMPnIA41s=', 'base64')
            }
        });

        await client.updateLastBlock();
    });
});