package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.bytes.NativeBytesStore;
import net.openhft.chronicle.core.annotation.NotNull;
import net.openhft.chronicle.core.annotation.Nullable;

import javax.xml.bind.DatatypeConverter;

import static net.openhft.chronicle.salt.Sodium.*;

public enum SealedBox {
    ;

    @NotNull
    public static BytesStore encrypt(@NotNull BytesStore message, @NotNull BytesStore publicKey) {
        return encrypt( null, message, publicKey );
    }

    @NotNull
    public static BytesStore encrypt(@Nullable BytesStore result, @NotNull BytesStore message, @NotNull BytesStore publicKey) {
        if (publicKey == null)
            throw new RuntimeException("Encryption failed. Public key not available.");

        long length = message.readRemaining();
        long resultLength = length + CRYPTO_BOX_SEALBYTES;
        result = Sodium.Util.setSize(result, resultLength);

        checkValid(SODIUM.crypto_box_seal(result.addressForWrite(0), message.addressForRead(message.readPosition()), (int) length,
                publicKey.addressForRead(publicKey.readPosition())), "Encryption failed");
        return result;
    }

    @NotNull
    public static BytesStore decrypt(@NotNull BytesStore ciphertext, @NotNull BytesStore publicKey, @NotNull BytesStore secretKey) {
        return decrypt( null, ciphertext, publicKey, secretKey);
    }

    @NotNull
    public static BytesStore decrypt(@Nullable BytesStore result, @NotNull BytesStore ciphertext, @NotNull BytesStore publicKey,
            @NotNull BytesStore secretKey) {
        if (publicKey == null)
            throw new RuntimeException("Decryption failed. Public key not available.");
        if (secretKey == null)
            throw new RuntimeException("Decryption failed. Private key not available.");

        long length = ciphertext.readRemaining();
        long resultLength = length - CRYPTO_BOX_SEALBYTES;
        result = Sodium.Util.setSize(result, resultLength);

        checkValid(
                SODIUM.crypto_box_seal_open(result.addressForWrite(0), ciphertext.addressForRead(ciphertext.readPosition()), (int) length,
                        publicKey.addressForRead(publicKey.readPosition()), secretKey.addressForRead(secretKey.readPosition())),
                "Decryption failed. Ciphertext failed verification");
        return result;
    }

    public static class KeyPair {

        public final BytesStore publicKey;
        public final BytesStore secretKey;

        public KeyPair() {
            this.secretKey = Bytes.allocateDirect(CRYPTO_BOX_SECRETKEYBYTES);
            this.publicKey = Bytes.allocateDirect(CRYPTO_BOX_PUBLICKEYBYTES);

            SODIUM.crypto_box_keypair(publicKey.addressForWrite(0), secretKey.addressForWrite(0));

            ((Bytes) publicKey).readLimit(CRYPTO_BOX_PUBLICKEYBYTES);
            ((Bytes) secretKey).readLimit(CRYPTO_BOX_SECRETKEYBYTES);
        }

        public KeyPair(long id) {
            this.secretKey = Bytes.allocateDirect(CRYPTO_BOX_SECRETKEYBYTES);
            this.publicKey = Bytes.allocateDirect(CRYPTO_BOX_PUBLICKEYBYTES);
            BytesStore seed = Bytes.allocateDirect(CRYPTO_BOX_SEEDBYTES);

            seed.writeLong(0, id);
            SODIUM.crypto_box_seed_keypair(publicKey.addressForWrite(0),
                    secretKey.addressForWrite(0),
                    seed.addressForWrite(0));

            ((Bytes) publicKey).readLimit(CRYPTO_BOX_PUBLICKEYBYTES);
            ((Bytes) secretKey).readLimit(CRYPTO_BOX_SECRETKEYBYTES);
        }
    }

}
