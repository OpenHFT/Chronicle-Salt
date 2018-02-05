package net.openhft.chronicle.salt;

import jnr.ffi.byref.LongLongByReference;
import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;

import static net.openhft.chronicle.salt.Sodium.SODIUM;
import static net.openhft.chronicle.salt.Sodium.checkValid;

public enum Ed25519 {
    ;

    private static final ThreadLocal<LocalEd25519> CACHED_CRYPTO = ThreadLocal.withInitial(LocalEd25519::new);
    public static int PRIVATE_KEY_LENGTH = 32;
    public static int PUBLIC_KEY_LENGTH = 32;
    public static int SECRET_KEY_LENGTH = PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH;
    public static int SIGNATURE_LENGTH = 64;

    public static Bytes generateRandomBytes(int length) {
        Bytes bytes = Bytes.allocateElasticDirect(length);
        SODIUM.randombytes(bytes.addressForWrite(0), length);
        bytes.readPositionRemaining(0, length);
        return bytes;
    }

    /*
    public static void privateToPublic(Bytes<?> publicKey, Bytes<?> privateKey) {
        if (privateKey.readRemaining() != PRIVATE_KEY_LENGTH) throw new IllegalArgumentException("privateKey");
        publicKey.ensureCapacity(PUBLIC_KEY_LENGTH);
        assert privateKey.isDirectMemory();
        assert publicKey.isDirectMemory();
    
        Sodium.SODIUM.crypto_scalarmult_curve25519(
                publicKey.addressForWrite(0),
                privateKey.addressForRead(privateKey.readPosition()),
                Sodium.SGE_BYTES.addressForRead(0)
        );
        publicKey.readPositionRemaining(0, PUBLIC_KEY_LENGTH);
    }
    
    public static void privateToSecret(Bytes<?> secretKey, Bytes<?> privateKey) {
        if (privateKey.readRemaining() != PRIVATE_KEY_LENGTH) throw new IllegalArgumentException("privateKey");
        secretKey.ensureCapacity(PUBLIC_KEY_LENGTH);
        assert privateKey.isDirectMemory();
        assert secretKey.isDirectMemory();
    
        long privateAddr = privateKey.addressForRead(privateKey.readPosition());
        OS.memory().copyMemory(privateAddr, secretKey.addressForWrite(0), PRIVATE_KEY_LENGTH);
        Sodium.SODIUM.crypto_scalarmult_curve25519(
                secretKey.addressForWrite(PRIVATE_KEY_LENGTH),
                privateAddr,
                Sodium.SGE_BYTES.addressForRead(0)
        );
        secretKey.readPositionRemaining(0, SECRET_KEY_LENGTH);
    }
    */

    public static void privateToPublicAndSecret(Bytes<?> publicKey, Bytes<?> secretKey, BytesStore privateKey) {
        if (privateKey.readRemaining() != PRIVATE_KEY_LENGTH) {
            throw new IllegalArgumentException("privateKey");
        }
        assert privateKey.refCount() > 0;
        assert secretKey.refCount() > 0;
        assert publicKey.refCount() > 0;
        publicKey.ensureCapacity(publicKey.writePosition() + PUBLIC_KEY_LENGTH);
        secretKey.ensureCapacity(secretKey.writePosition() + SECRET_KEY_LENGTH);
        assert privateKey.isDirectMemory();
        assert secretKey.isDirectMemory();
        assert publicKey.isDirectMemory();

        SODIUM.crypto_sign_ed25519_seed_keypair(publicKey.addressForWrite(publicKey.writePosition()),
                secretKey.addressForWrite(secretKey.writePosition()), privateKey.addressForRead(privateKey.readPosition()));
        publicKey.readPositionRemaining(publicKey.writePosition(), PUBLIC_KEY_LENGTH);
        secretKey.readPositionRemaining(secretKey.writePosition(), SECRET_KEY_LENGTH);
    }

    /*
    public static void generateKey(Bytes<?> privateKey, Bytes<?> publicKey) {
        privateKey.ensureCapacity(PRIVATE_KEY_LENGTH);
        publicKey.ensureCapacity(PUBLIC_KEY_LENGTH);
        assert privateKey.isDirectMemory();
        assert publicKey.isDirectMemory();
    
        long privateKeyAddr = privateKey.addressForWrite(0);
        long publicKeyAddr = publicKey.addressForWrite(0);
        checkValid(
                Sodium.SODIUM.crypto_box_curve25519xsalsa20poly1305_keypair(publicKeyAddr, privateKeyAddr),
                "generate key");
        privateKey.readPositionRemaining(0, PRIVATE_KEY_LENGTH);
        publicKey.readPositionRemaining(0, PUBLIC_KEY_LENGTH);
    }
    */

    public static void sign(Bytes sigAndMsg, BytesStore message, BytesStore secretKey) {
        sigAndMsg.ensureCapacity(sigAndMsg.writePosition() + SIGNATURE_LENGTH + message.readRemaining());
        assert sigAndMsg.refCount() > 0;
        assert message.refCount() > 0;
        assert secretKey.refCount() > 0;
        assert sigAndMsg.isDirectMemory();
        assert message.isDirectMemory();
        assert secretKey.isDirectMemory();

        if (secretKey.readRemaining() != SECRET_KEY_LENGTH) {
            throw new IllegalArgumentException("Must be a secretKey");
        }
        CACHED_CRYPTO.get().sign(sigAndMsg, message, secretKey);
    }

    public static boolean verify(BytesStore sigAndMsg, BytesStore publicKey) {
        assert sigAndMsg.refCount() > 0;
        assert publicKey.refCount() > 0;
        assert sigAndMsg.isDirectMemory();
        assert publicKey.isDirectMemory();

        if (sigAndMsg.readRemaining() < SIGNATURE_LENGTH) {
            throw new IllegalArgumentException("sigAndMsg");
        }
        if (publicKey.readRemaining() != PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("publicKey");
        }
        return CACHED_CRYPTO.get().verify(sigAndMsg, publicKey);
    }

    public static void generatePrivateKey(Bytes privateKey) {
        assert privateKey.refCount() > 0;
        privateKey.ensureCapacity(PRIVATE_KEY_LENGTH);
        assert privateKey.isDirectMemory();
        SODIUM.randombytes(privateKey.addressForWrite(0), PRIVATE_KEY_LENGTH);
        privateKey.readPositionRemaining(0, PRIVATE_KEY_LENGTH);
    }

    public static Bytes generatePrivateKey() {
        Bytes privateKey = Bytes.allocateDirect(PRIVATE_KEY_LENGTH);
        generatePrivateKey(privateKey);
        return privateKey;
    }

    static class LocalEd25519 {

        final LongLongByReference sigLen = new LongLongByReference(0);
        final Bytes buffer = Bytes.allocateElasticDirect(64); // no idea. Required but doesn't appear to be used.

        void sign(Bytes sigAndMsg, BytesStore message, BytesStore secretKey) {
            int msgLen = (int) message.readRemaining();
            checkValid(SODIUM.crypto_sign_ed25519(
                    sigAndMsg.addressForWrite(sigAndMsg.writePosition()),
                    sigLen,
                    message.addressForRead(message.readPosition()),
                    msgLen,
                    secretKey.addressForRead(secretKey.readPosition())),
                    "Unable to sign");
            long bytesToSkip = sigLen.longValue();
            sigAndMsg.writeSkip(bytesToSkip);
        }

        boolean verify(BytesStore sigAndMsg, BytesStore publicKey) {
            int length = sigAndMsg.length();
            buffer.ensureCapacity(length);
            int ret = SODIUM.crypto_sign_ed25519_open(
                    buffer.addressForWrite(0),
                    sigLen,
                    sigAndMsg.addressForRead(sigAndMsg.readPosition()),
                    (int) sigAndMsg.readRemaining(),
                    publicKey.addressForRead(publicKey.readPosition()));
            long l = sigLen.longValue();
            assert l <= length;
            return ret == 0;
        }
    }
}
