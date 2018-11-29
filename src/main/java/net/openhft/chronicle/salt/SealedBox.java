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

    private static final String STANDARD_GROUP_ELEMENT = "0900000000000000000000000000000000000000000000000000000000000000";
    private static final BytesStore STANDARD_GROUP_ELEMENT_BYTES =
            NativeBytesStore.from(
                    DatatypeConverter.parseHexBinary(STANDARD_GROUP_ELEMENT));

    @NotNull
    public static BytesStore encrypt(@Nullable BytesStore result, @NotNull BytesStore message, @NotNull BytesStore publicKey) {
        if (publicKey == null)
            throw new RuntimeException("Encryption failed. Public key not available.");
        long length = message.readRemaining();
        long resultLength = length + CRYPTO_BOX_SEALBYTES;
        result = Sodium.Util.setSize(result, resultLength);
        checkValid(
                SODIUM.crypto_box_seal(
                        result.addressForWrite(0),
                        message.addressForRead(message.readPosition()),
                        (int) length,
                        publicKey.addressForRead(publicKey.readPosition())),
                "Encryption failed");
        return result;
    }

    @NotNull
    public static BytesStore decrypt(@Nullable BytesStore result, @NotNull BytesStore ciphertext, @NotNull BytesStore publicKey, @NotNull BytesStore secrectKey) {
        if (publicKey == null)
            throw new RuntimeException("Decryption failed. Public key not available.");
        if (secrectKey == null)
            throw new RuntimeException("Decryption failed. Private key not available.");

        long length = ciphertext.readRemaining();
        long resultLength = length - CRYPTO_BOX_SEALBYTES;
        result = Sodium.Util.setSize(result, resultLength);

        checkValid(
                SODIUM.crypto_box_seal_open(
                        result.addressForWrite(0),
                        ciphertext.addressForRead(ciphertext.readPosition()),
                        (int) length,
                        publicKey.addressForRead(publicKey.readPosition()),
                        secrectKey.addressForRead(secrectKey.readPosition())),
                "Decryption failed. Ciphertext failed verification");
        return result;
    }

    @NotNull
    static BytesStore pointMult(@Nullable Bytes result, @NotNull BytesStore a) {
        return pointMult(result, a, STANDARD_GROUP_ELEMENT_BYTES);
    }

    @NotNull
    static BytesStore pointMult(@Nullable BytesStore result, @NotNull BytesStore a, @NotNull BytesStore b) {
        long resultLength = CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES;
        result = Sodium.Util.setSize(result, resultLength);

        checkValid(
                SODIUM.crypto_scalarmult_curve25519(
                        result.addressForWrite(0),
                        a.addressForRead(a.readPosition()),
                        b.addressForWrite(b.readPosition())),
                "Unable to point multiply");
        return result;
    }

    public static class KeyPair {

        public final BytesStore publicKey;
        public final BytesStore secretKey;

        public KeyPair() {
            this.secretKey = Bytes.allocateDirect(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES);
            this.publicKey = Bytes.allocateDirect(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES);
            SODIUM.crypto_box_curve25519xsalsa20poly1305_keypair(
                    publicKey.addressForWrite(0),
                    secretKey.addressForWrite(0));
            ((Bytes) publicKey).readLimit(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES);
            ((Bytes) secretKey).readLimit(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES);
        }

        public KeyPair(BytesStore secretKey) {
            this.secretKey = secretKey;
            if (this.secretKey.readRemaining() != CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES)
                throw new IllegalArgumentException("secretKey the wrong length");
            this.publicKey = pointMult(null, secretKey);
        }

        public KeyPair(long id) {
            secretKey = NativeBytesStore.nativeStoreWithFixedCapacity(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES);
            secretKey.zeroOut(0, CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES);
            secretKey.writeLong(CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES - Long.BYTES, id);
            this.publicKey = pointMult(null, secretKey);
        }
    }

}
