package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;

public enum Ed25519 implements Crypto {
    INSTANCE;

    private static final ThreadLocal<LocalEd25519> CACHED_CRYPTO = ThreadLocal.withInitial(LocalEd25519::new);


    @Override
    public void initialiseForWrite(Bytes bytes) {
        bytes.clear();
        bytes.zeroOut(0, 64);
        bytes.writePosition(64);
    }

    @Override
    public void generateKey(Bytes<?> privateKey, Bytes<?> publicKey) {
        LocalEd25519 le = CACHED_CRYPTO.get();
        le.generateKey(privateKey, publicKey);
    }

    @Override
    public void sign(BytesStore bytes, BytesStore privateKey) {
        LocalEd25519 le = CACHED_CRYPTO.get();
        le.sign(bytes, privateKey);
    }

    @Override
    public boolean verify(BytesStore bytes, BytesStore publicKey) {
        LocalEd25519 le = CACHED_CRYPTO.get();
        return le.verify(bytes, publicKey);
    }

    static class LocalEd25519 {

        void generateKey(Bytes<?> privateKey, Bytes<?> publicKey) {

        }

        void sign(BytesStore bytes, BytesStore privateKey) {

        }


        public boolean verify(BytesStore bytes, BytesStore publicKey) {
            return false;
        }
    }
}
