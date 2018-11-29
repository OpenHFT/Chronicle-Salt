package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.core.annotation.NotNull;
import net.openhft.chronicle.core.annotation.Nullable;

import static net.openhft.chronicle.salt.Sodium.*;

public enum EasyBox {
    ;

    public static BytesStore nonce() {
        return nonce(null);
    }

    public static BytesStore nonce(@Nullable BytesStore bytes) {
        BytesStore ret = Sodium.Util.setSize(bytes, CRYPTO_BOX_NONCEBYTES);
        SODIUM.randombytes(ret.addressForRead(0), CRYPTO_BOX_NONCEBYTES);
        return ret;
    }

    public static BytesStore encrypt(BytesStore result, BytesStore message, BytesStore nonce, BytesStore publicKey, BytesStore secrectKey) {
        if (publicKey == null)
            throw new RuntimeException("Encryption failed. Public key not available.");
        long length = message.readRemaining();
        long resultLength = length + CRYPTO_BOX_MACBYTES;
        result = Sodium.Util.setSize(result, resultLength);
        checkValid(
                SODIUM.crypto_box_easy(
                        result.addressForWrite(0),
                        message.addressForRead(message.readPosition()),
                        (int) length,
                        nonce.addressForRead(nonce.readPosition()),
                        publicKey.addressForRead(publicKey.readPosition()),
                        secrectKey.addressForRead(secrectKey.readPosition())),
                "Encryption failed");
        return result;
    }

    @NotNull
    public static BytesStore decrypt(@Nullable BytesStore result, @NotNull BytesStore ciphertext, BytesStore nonce, BytesStore publicKey, BytesStore secrectKey) {
        if (publicKey == null)
            throw new RuntimeException("Decryption failed. Public key not available.");
        if (secrectKey == null)
            throw new RuntimeException("Decryption failed. Private key not available.");

        long length = ciphertext.readRemaining();
        long resultLength = length - CRYPTO_BOX_MACBYTES;
        result = Sodium.Util.setSize(result, resultLength);

        checkValid(
                SODIUM.crypto_box_open_easy(
                        result.addressForWrite(0),
                        ciphertext.addressForRead(ciphertext.readPosition()),
                        (int) length,
                        nonce.addressForRead(nonce.readPosition()),
                        publicKey.addressForRead(publicKey.readPosition()),
                        secrectKey.addressForRead(secrectKey.readPosition())),
                "Decryption failed. Ciphertext failed verification");
        return result;
    }


    public static class KeyPair {

        public final BytesStore publicKey;
        public final BytesStore secretKey;

        public KeyPair() {
            this.secretKey = Bytes.allocateDirect(CRYPTO_BOX_SECRETKEYBYTES);
            this.publicKey = Bytes.allocateDirect(CRYPTO_BOX_PUBLICKEYBYTES);
            SODIUM.crypto_box_keypair(
                    publicKey.addressForWrite(0),
                    secretKey.addressForWrite(0));
            ((Bytes) publicKey).readLimit(CRYPTO_BOX_PUBLICKEYBYTES);
            ((Bytes) secretKey).readLimit(CRYPTO_BOX_SECRETKEYBYTES);
        }
    }
}
