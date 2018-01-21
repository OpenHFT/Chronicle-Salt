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

    public static void sign(Bytes sigAndMsg, BytesStore message, BytesStore privateKey) {
        CACHED_CRYPTO.get().sign(sigAndMsg, message, privateKey);
    }

    public static boolean verify(BytesStore bytes, BytesStore publicKey) {
        LocalEd25519 le = CACHED_CRYPTO.get();
        return le.verify(bytes, publicKey);
    }

    static class LocalEd25519 {

        final LongLongByReference sigLen = new LongLongByReference(0);

        void sign(Bytes sigAndMsg, BytesStore message, BytesStore privateKey) {
            checkValid(SODIUM.crypto_sign_ed25519(
                    sigAndMsg.addressForWrite(0),
                    sigLen,
                    message.addressForRead(message.readPosition()),
                    (int) message.readRemaining(),
                    privateKey.addressForRead(0)),
                    "Unable to sign");
            sigAndMsg.readPositionRemaining(0, 64 + message.readRemaining());
        }


        public boolean verify(BytesStore bytes, BytesStore publicKey) {
            return false;
        }
    }
}
