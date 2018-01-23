package net.openhft.chronicle.salt;

import jnr.ffi.byref.LongLongByReference;
import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;

import static net.openhft.chronicle.salt.Sodium.SODIUM;
import static net.openhft.chronicle.salt.Sodium.checkValid;

public enum Ed25519 {
    ;

    private static final ThreadLocal<LocalEd25519> CACHED_CRYPTO = ThreadLocal.withInitial(LocalEd25519::new);


    public static void initialiseForWrite(Bytes bytes) {
        bytes.clear();
        bytes.zeroOut(0, 64);
        bytes.writePosition(64);
    }

   /* public static void secretKey(Bytes<?> secretKey, Bytes<?> privateKey) {
        long privateKeyAddr = privateKey.addressForRead(0);
        long secretKeyAddr = secretKey.addressForWrite(0);
        long publicKeyAddr = secretKey.addressForWrite(32);
        OS.memory().copyMemory(privateKeyAddr, secretKeyAddr, 32);
        checkValid(
                Sodium.SODIUM.crypto_box_curve25519xsalsa20poly1305_keypair(publicKeyAddr, privateKeyAddr),
                "secret key");
        secretKey.readPositionRemaining(0, 64);
    }*/

    public static void privateToPublic(Bytes<?> publicKey, Bytes<?> privateKey) {
        Sodium.SODIUM.crypto_scalarmult_curve25519(
                publicKey.addressForWrite(0),
                privateKey.addressForRead(0),
                Sodium.SGE_BYTES.addressForRead(0)
        );
        publicKey.readPositionRemaining(0, 32);
    }

    public static void privateToPublicAndSecret(Bytes<?> publicKey, Bytes<?> secretKey, Bytes<?> privateKey) {
        SODIUM.crypto_sign_ed25519_seed_keypair(
                publicKey.addressForWrite(0),
                secretKey.addressForWrite(0),
                privateKey.addressForRead(0)
        );
        publicKey.readPositionRemaining(0, 32);
        secretKey.readPositionRemaining(0, 64);
    }

    public static void generateKey(Bytes<?> privateKey, Bytes<?> publicKey) {
        long privateKeyAddr = privateKey.addressForWrite(0);
        long publicKeyAddr = publicKey.addressForWrite(0);
        checkValid(
                Sodium.SODIUM.crypto_box_curve25519xsalsa20poly1305_keypair(publicKeyAddr, privateKeyAddr),
                "secret key");
        privateKey.readPositionRemaining(0, 32);
        publicKey.readPositionRemaining(0, 32);
    }

    public static void sign(Bytes sigAndMsg, BytesStore message, BytesStore secretKey) {
        if (secretKey.readRemaining() != 64) throw new IllegalArgumentException("Must be a secretKey");
        CACHED_CRYPTO.get().sign(sigAndMsg, message, secretKey);
    }

    public static boolean verify(BytesStore sigAndMsg, BytesStore publicKey) {
        if (sigAndMsg.readRemaining() < 64) throw new IllegalArgumentException("sigAAndMsg");
        if (publicKey.readRemaining() != 32) throw new IllegalArgumentException("publicKey");
        return CACHED_CRYPTO.get().verify(sigAndMsg, publicKey);
    }

    static class LocalEd25519 {

        final LongLongByReference sigLen = new LongLongByReference(0);
        final Bytes buffer = Bytes.allocateElasticDirect(64);

        void sign(Bytes sigAndMsg, BytesStore message, BytesStore secretKey) {
            int msgLen = (int) message.readRemaining();
            checkValid(SODIUM.crypto_sign_ed25519(
                    sigAndMsg.addressForWrite(0),
                    sigLen,
                    message.addressForRead(message.readPosition()),
                    msgLen,
                    secretKey.addressForRead(0)),
                    "Unable to sign");
            sigAndMsg.readPositionRemaining(0, sigLen.longValue());
        }


        boolean verify(BytesStore sigAndMsg, BytesStore publicKey) {
//            buffer.ensureCapacity(sigAndMsg.length());
            int ret = SODIUM.crypto_sign_ed25519_open(
                    buffer.addressForWrite(0),
                    sigLen,
                    sigAndMsg.addressForRead(sigAndMsg.readPosition()),
                    (int) sigAndMsg.readRemaining(),
                    publicKey.addressForRead(publicKey.readPosition()));
            assert sigLen.longValue() <= 64;
//            System.out.println("sigLen: " + sigLen.longValue() + " ret: " + ret);
            return ret == 0;
        }
    }
}
