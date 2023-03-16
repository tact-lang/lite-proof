export interface ProofStorage {
    storeProof(key: string, value: string): Promise<void>;
    loadProof(key: string): Promise<string | null>;
}

export function createMemoryStorage() {
    const storage = new Map<string, string>();
    return {
        storeProof(key: string, value: string): Promise<void> {
            storage.set(key, value);
            return Promise.resolve();
        },
        loadProof(key: string): Promise<string | null> {
            return Promise.resolve(storage.get(key) || null);
        }
    } satisfies ProofStorage;
}