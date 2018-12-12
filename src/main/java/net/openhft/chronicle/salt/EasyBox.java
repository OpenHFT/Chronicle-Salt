package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.core.annotation.NotNull;
import net.openhft.chronicle.core.annotation.Nullable;

import static net.openhft.chronicle.salt.Sodium.*;

public enum EasyBox {
    ;

    /**
     * Generate nonce
     * Should only be used for single exchange then refreshed
     * @return - the nonce BytesStore
     */
    public static BytesStore nonce() {
        return nonce(null);
    }

    public static BytesStore nonce(@Nullable BytesStore bytes) {
        BytesStore ret = Sodium.Util.setSize(bytes, CRYPTO_BOX_NONCEBYTES);
        SODIUM.randombytes_buf(ret.addressForRead(0), CRYPTO_BOX_NONCEBYTES);
        return ret;
    }

    public static BytesStore nextNonce( BytesStore nonce )
    {
        SODIUM.sodium_increment( nonce.addressForWrite(0), CRYPTO_BOX_NONCEBYTES);
        return nonce;
    }
    /**
     * Generate deterministic nonce
     * Should only be used for single exchange then refreshed
     * @param id - the seed
     * @return - the nonce Bytes
     */
    public static BytesStore nonce( long id ) {
        return nonce(null, id );
    }

    public static BytesStore nonce( @Nullable BytesStore bytes, long id ) {
        BytesStore seed = Bytes.allocateDirect(RANDOMBYTES_SEEDBYTES);
        seed.writeLong(0, id );

        BytesStore ret = Sodium.Util.setSize(bytes, CRYPTO_BOX_NONCEBYTES);
        SODIUM.randombytes_buf_deterministic(ret.addressForRead(0), CRYPTO_BOX_NONCEBYTES, seed.addressForWrite(0));
        return ret;

    }

    /**
     * Encrypt a message given a nonce, receivers public key, and own private key
     * @param message - the cleartext message
     * @param nonce - one-off tag associated with this message exchange. Public
     * @param publicKey - the recipients public key
     * @param secretKey - the sender's private key
     * @return - the ciphertext BytesStore corresponding to the clearText message
     */
    public static BytesStore encrypt(BytesStore message, BytesStore nonce, BytesStore publicKey, BytesStore secretKey) {
        return encrypt( null, message, nonce, publicKey, secretKey);
    }

    /**
     * As above, but result BytesStore is passed in first arg
     * @param result - the ByteStore for the ciphertext result
     * remaining params as above
     * @return - the ciphertext BytesStore (echoes arg1)
     */
    public static BytesStore encrypt(BytesStore result, BytesStore message, BytesStore nonce, BytesStore publicKey, BytesStore secretKey) {
        if (publicKey == null)
            throw new RuntimeException("Encryption failed. Public key not available.");
        if (secretKey == null)
            throw new RuntimeException("Encryption failed. Private key not available.");

        long length = message.readRemaining();
        long resultLength = length + CRYPTO_BOX_MACBYTES;
        result = Sodium.Util.setSize(result, resultLength);

        checkValid(Bridge.crypto_box_easy(result.addressForWrite(0), message.addressForRead(message.readPosition()), length,
                nonce.addressForRead(nonce.readPosition()), publicKey.addressForRead(publicKey.readPosition()),
                secretKey.addressForRead(secretKey.readPosition())), "Encryption failed");

        return result;
    }

    /**
     * Encrypt a message given a nonce and a *shared* secret key
     * The shared key should be precalculated using KeyPair.precalc
     * Using a shared key can substantially improve performance when the same sender/receiver exchange many messages
     * @param message - the cleartext message
     * @param nonce - one-off tag associated with this message exchange. Public
     * @param sharedKey - the shared key formed from recipient's public and sender's private key
     * @return - the ciphertext BytesStore corresponding to the clearText message
     */
    public static BytesStore encryptShared(BytesStore message, BytesStore nonce, BytesStore sharedKey) {
        return encryptShared( null, message, nonce, sharedKey );
    }

    /**
     * As above, but result BytesStore is passed in first arg
     * @param result - the BytesStore for the ciphertext result
     * remaining params as above
     * @return - the ciphertext BytesStore (echoes arg1)
     */
    public static BytesStore encryptShared(BytesStore result, BytesStore message, BytesStore nonce, BytesStore sharedKey) {
        if (sharedKey == null)
            throw new RuntimeException("Encryption failed. Shared key not available.");

        long length = message.readRemaining();
        long resultLength = length + CRYPTO_BOX_MACBYTES;
        result = Sodium.Util.setSize(result, resultLength);

        checkValid(SODIUM.crypto_box_easy_afternm(result.addressForWrite(0), message.addressForRead(message.readPosition()), length,
                nonce.addressForRead(nonce.readPosition()), sharedKey.addressForRead(sharedKey.readPosition())), "Encryption failed");

        return result;
    }

    /**
     * Decrypt a message given a nonce, sender's public key, and receiver's private key
     * @param ciphertext - the encrypted message
     * @param nonce - one-off tag associated with this message exchange. Public
     * @param publicKey - sender's public key
     * @param secretKey - receriver's private key
     * @return - the cleartext BytesStore
     */
    @NotNull
    public static BytesStore decrypt(@NotNull BytesStore ciphertext, BytesStore nonce, BytesStore publicKey,BytesStore secretKey) {
        return decrypt( null, ciphertext, nonce, publicKey, secretKey );
    }

    /**
     * As above, but result BytesStore is passed in first arg
     * @param result - the BytesStore for the cleartext result
     * remaining params as above
     * @return - the cleartext BytesStore (echoes arg1)
     */
    public static BytesStore decrypt(@Nullable BytesStore result, @NotNull BytesStore ciphertext, BytesStore nonce, BytesStore publicKey,
            BytesStore secretKey) {
        if (publicKey == null)
            throw new RuntimeException("Decryption failed. Public key not available.");
        if (secretKey == null)
            throw new RuntimeException("Decryption failed. Private key not available.");

        long length = ciphertext.readRemaining();
        long resultLength = length - CRYPTO_BOX_MACBYTES;
        result = Sodium.Util.setSize(result, resultLength);

        checkValid(Bridge.crypto_box_open_easy(result.addressForWrite(0), ciphertext.addressForRead(ciphertext.readPosition()), length,
                nonce.addressForRead(nonce.readPosition()), publicKey.addressForRead(publicKey.readPosition()),
                secretKey.addressForRead(secretKey.readPosition())), "Decryption failed. Ciphertext failed verification");

        return result;
    }

    /**
     * Decrypt a message given a nonce and a *shared* secret key
     * The shared key should be precalculated using KeyPair.precalc
     * Using a shared key can substantially improve performance when the same sender/receiver exchange many messages
     * @param ciphertext - the ciphertext message
     * @param nonce - one-off tag associated with this message exchange. Public
     * @param sharedKey - the shared key formewd from sender's public and recipient's private key
     * @return - the cleartext BytesStore corresponding to the cipherText message
     */
    public static BytesStore decryptShared(@NotNull BytesStore ciphertext, BytesStore nonce, BytesStore sharedKey) {
        return decryptShared( null, ciphertext, nonce, sharedKey);
    }

    /**
     * As above, but result BytesStore is passed in first arg
     * @param result - the BytesStore for the cleartext result
     * remaining params as above
     * @return - the cleartext BytesStore (echoes arg1)
     */
    public static BytesStore decryptShared(@Nullable BytesStore result, @NotNull BytesStore ciphertext, BytesStore nonce, BytesStore sharedKey) {
        if (sharedKey == null)
            throw new RuntimeException("Decryption failed. Shared key not available.");

        long length = ciphertext.readRemaining();
        long resultLength = length - CRYPTO_BOX_MACBYTES;
        result = Sodium.Util.setSize(result, resultLength);

        checkValid(SODIUM.crypto_box_open_easy_afternm(result.addressForWrite(0), ciphertext.addressForRead(ciphertext.readPosition()), length,
                nonce.addressForRead(nonce.readPosition()), sharedKey.addressForRead(sharedKey.readPosition())), "Decryption failed. Ciphertext failed verification");

        return result;
    }

    /**
     * Helper class to manage KeyPairs for EasyBox message exchange
     */
    public static class KeyPair {
        public final BytesStore publicKey;
        public final BytesStore secretKey;

        /**
         * Generate random public/private key pair
         */
        public KeyPair() {
            this.secretKey = Bytes.allocateDirect(CRYPTO_BOX_SECRETKEYBYTES);
            this.publicKey = Bytes.allocateDirect(CRYPTO_BOX_PUBLICKEYBYTES);

            SODIUM.crypto_box_keypair(publicKey.addressForWrite(0), secretKey.addressForWrite(0));

            ((Bytes) publicKey).readLimit(CRYPTO_BOX_PUBLICKEYBYTES);
            ((Bytes) secretKey).readLimit(CRYPTO_BOX_SECRETKEYBYTES);
        }

        /**
         * Generate deterministic public/private key pair
         * @param id - deterministic seed
         */
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

        /**
         * Precalculate the shared secret key given the public and private part of separate keys
         * This can be used to substantially improve performance when a given sender/receiver
         * exchange multiple messages
         * NOTE: intentionally takes distinct public and private keys rather than a single KeyPair instance as the key components
         *       will normally be complementary parts from two different KeyPairs
         * @param publicKey - the remote side's public key
         * @param secretKey - own secret key
         * @return - the shared secret key for message exchange
         */
        public static BytesStore precalc( BytesStore publicKey, BytesStore secretKey )
        {
            BytesStore shared = Bytes.allocateDirect(CRYPTO_BOX_BEFORENMBYTES);
            SODIUM.crypto_box_beforenm( shared.addressForWrite(0),publicKey.addressForRead(0), secretKey.addressForRead(0));

            ((Bytes)shared).readLimit(CRYPTO_BOX_BEFORENMBYTES);
            return shared;
        }
    }
}
