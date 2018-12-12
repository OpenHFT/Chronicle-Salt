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

    /**
     * Anonymously encrypt a message given a receivers public key
     * @param message - the cleartext message
     * @param publicKey - the recipients public key
     * @return - the ciphertext BytesStore corresponding to the clearText message
     */
    @NotNull
    public static BytesStore encrypt(@NotNull BytesStore message, @NotNull PublicKey publicKey) {
        return encrypt( null, message, publicKey );
    }

    /**
     * As above, but result BytesStore is passed in first arg
     * @param result - the ByteStore for the ciphertext result
     * remaining params as above
     * @return - the ciphertext BytesStore (echoes arg1)
     */
    @NotNull
    public static BytesStore encrypt(@Nullable BytesStore result, @NotNull BytesStore message, @NotNull PublicKey publicKey) {
        return encrypt( result, message, publicKey.store );
    }

    /**
     * Underlying encrypt call taking explicit BytesStores
     * Where possible the strongly-typed versions above should be preferred
     */
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

    /**
     * Decrypt a message given own (receiver's) public and secret keys
     * @param ciphertext - the encrypted message
     * @param publicKey - receiver's public key
     * @param secretKey - receiver's private key
     * @return - the cleartext BytesStore
     */
    @NotNull
    public static BytesStore decrypt(@NotNull BytesStore ciphertext, @NotNull PublicKey publicKey, @NotNull SecretKey secretKey) {
        return decrypt( null, ciphertext, publicKey, secretKey);
    }

    /**
     * As above, but result BytesStore is passed in first arg
     * @param result - the BytesStore for the cleartext result
     * remaining params as above
     * @return - the cleartext BytesStore (echoes arg1)
     */
    @NotNull
    public static BytesStore decrypt(@Nullable BytesStore result, @NotNull BytesStore ciphertext, @NotNull PublicKey publicKey,  @NotNull SecretKey secretKey) {
        return decrypt( result, ciphertext, publicKey.store, secretKey.store );
    }

    /**
     * Underlying decrypt call taking explicit BytesStores
     * Where possible the strongly-typed versions above should be preferred
     */
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

    /**
     * Helper class to manage the public part of a KeyPair
     * A PublicKey is created internally as part of a KeyPair, and provides a strongly-typed wrapper over the underlying BytesStore
     */
    public static class PublicKey
    {
        public final BytesStore store;

        private PublicKey()
        {
            this.store = Bytes.allocateDirect(CRYPTO_BOX_PUBLICKEYBYTES);
            ((Bytes) store).readLimit(CRYPTO_BOX_PUBLICKEYBYTES);
        }

        public long address()
        {
            return store.addressForRead(0);
        }
    }

    /**
     * Helper class to manage the secret part of a KeyPair
     * A SecretKey is created internally as part of a KeyPair, and provides a strongly-typed wrapper over the underlying BytesStore
     */
    public static class SecretKey
    {
        public final BytesStore store;

        private SecretKey()
        {
            this.store = Bytes.allocateDirect(CRYPTO_BOX_SECRETKEYBYTES);
            ((Bytes) store).readLimit(CRYPTO_BOX_SECRETKEYBYTES);
        }

        public long address()
        {
            return store.addressForRead(0);
        }
    }

    /**
     * Helper class to handle KeyPair creation
     * Explicitly named static methods are provided for consistency with EasyBox where they differentiate normal vs deterministic calls
     * (As noted below, deterministic calls are not meaningful for sealed boxes)
     */
    public static class KeyPair {
        public final PublicKey publicKey;
        public final SecretKey secretKey;

        /**
         * Generate random public/private key pair
         */
        public static KeyPair generate()
        {
            return new KeyPair();
        }

        private KeyPair() {
            this.secretKey = new SecretKey();
            this.publicKey = new PublicKey();

            SODIUM.crypto_box_keypair(publicKey.address(), secretKey.address());
        }

        /**
         * NB: For SealedBox, deterministic keys are of no use as the ephemeral key pair which libsodium sealed boxes use
         * under the hood is not exposed and cannot be controlled. As a result, even with a deterministic key pair for
         * the receiver the ciphertext for a given cleartext will change from run to run
         */
    }

}
