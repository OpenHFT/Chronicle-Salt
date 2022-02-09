package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import static net.openhft.chronicle.salt.Sodium.*;

public enum EasyBox {
    ; // none

    /**
     * Encrypt a message given a nonce, receivers public key, and own private key
     *
     * @param message
     *            - the cleartext message
     * @param nonce
     *            - one-off tag associated with this message exchange. Public
     * @param publicKey
     *            - the recipients public key
     * @param secretKey
     *            - the sender's private key
     * @return - the ciphertext BytesStore corresponding to the clearText message
     */
    public static BytesStore encrypt(BytesStore message, Nonce nonce, PublicKey publicKey, SecretKey secretKey) {
        return encrypt(null, message, nonce, publicKey, secretKey);
    }

    /**
     * As above, but result BytesStore is passed in first arg
     *
     * @param result
     *            - the ByteStore for the ciphertext result remaining params as above
     * @param message
     *            - the cleartext message
     * @param nonce
     *            - one-off tag associated with this message exchange. Public
     * @param publicKey
     *            - the recipients public key
     * @param secretKey
     *            - the sender's private key
     * @return - the ciphertext BytesStore (echoes arg1)
     */
    public static BytesStore encrypt(BytesStore result, BytesStore message, Nonce nonce, PublicKey publicKey, SecretKey secretKey) {
        return encrypt(result, message, nonce.store, publicKey.store, secretKey.store);
    }

    /**
     * Underlying encrypt call taking explicit BytesStores Where possible the strongly-typed versions above should be preferred
     *
     * @param result
     *            - the ByteStore for the ciphertext result remaining params as above
     * @param message
     *            - the cleartext message
     * @param nonce
     *            - one-off tag associated with this message exchange. Public
     * @param publicKey
     *            - the recipients public key
     * @param secretKey
     *            - the sender's private key
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
     * Encrypt a message given a nonce and a *shared* secret key The shared key should be precalculated using KeyPair.precalc Using a shared
     * key can substantially improve performance when the same sender/receiver exchange many messages
     *
     * @param message
     *            - the cleartext message
     * @param nonce
     *            - one-off tag associated with this message exchange. Public
     * @param sharedKey
     *            - the shared key formed from recipient's public and sender's private key
     * @return - the ciphertext BytesStore corresponding to the clearText message
     */
    public static BytesStore encryptShared(BytesStore message, Nonce nonce, SharedKey sharedKey) {
        return encryptShared(null, message, nonce, sharedKey);
    }

    /**
     * As above, but result BytesStore is passed in first arg
     *
     * @param result
     *            - the BytesStore for the ciphertext result remaining params as above
     * @param message
     *            - the cleartext message
     * @param nonce
     *            - one-off tag associated with this message exchange. Public
     * @param sharedKey
     *            - the shared key formed from recipient's public and sender's private key
     * @return - the ciphertext BytesStore (echoes arg1)
     */
    public static BytesStore encryptShared(BytesStore result, BytesStore message, Nonce nonce, SharedKey sharedKey) {
        return encryptShared(result, message, nonce.store, sharedKey.store);
    }

    /**
     * Underlying encryptShared call taking explicit BytesStores Where possible the strongly-typed versions above should be preferred
     *
     * @param result
     *            - the BytesStore for the ciphertext result remaining params as above
     * @param message
     *            - the cleartext message
     * @param nonce
     *            - one-off tag associated with this message exchange. Public
     * @param sharedKey
     *            - the shared key formed from recipient's public and sender's private key
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
     *
     * @param ciphertext
     *            - the encrypted message
     * @param nonce
     *            - one-off tag associated with this message exchange. Public
     * @param publicKey
     *            - sender's public key
     * @param secretKey
     *            - receiver's private key
     * @return - the cleartext BytesStore
     */
    @NotNull
    public static BytesStore decrypt(@NotNull BytesStore ciphertext, Nonce nonce, PublicKey publicKey, SecretKey secretKey) {
        return decrypt(null, ciphertext, nonce, publicKey, secretKey);
    }

    /**
     * As above, but result BytesStore is passed in first arg
     *
     * @param result
     *            - the BytesStore for the cleartext result remaining params as above
     * @param ciphertext
     *            - the encrypted message
     * @param nonce
     *            - one-off tag associated with this message exchange. Public
     * @param publicKey
     *            - sender's public key
     * @param secretKey
     *            - receiver's private key
     * @return - the cleartext BytesStore (echoes arg1)
     */
    public static BytesStore decrypt(@Nullable BytesStore result, @NotNull BytesStore ciphertext, Nonce nonce, PublicKey publicKey,
            SecretKey secretKey) {
        return decrypt(result, ciphertext, nonce.store, publicKey.store, secretKey.store);
    }

    /**
     * Underlying decrypt call taking explicit BytesStores Where possible the strongly-typed versions above should be preferred
     *
     * @param result
     *            - the BytesStore for the cleartext result remaining params as above
     * @param ciphertext
     *            - the encrypted message
     * @param nonce
     *            - one-off tag associated with this message exchange. Public
     * @param publicKey
     *            - sender's public key
     * @param secretKey
     *            - receiver's private key
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
     * Decrypt a message given a nonce and a *shared* secret key The shared key should be precalculated using KeyPair.precalc Using a shared
     * key can substantially improve performance when the same sender/receiver exchange many messages
     *
     * @param ciphertext
     *            - the ciphertext message
     * @param nonce
     *            - one-off tag associated with this message exchange. Public
     * @param sharedKey
     *            - the shared key formed from sender's public and recipient's private key
     * @return - the cleartext BytesStore corresponding to the cipherText message
     */
    public static BytesStore decryptShared(@NotNull BytesStore ciphertext, Nonce nonce, SharedKey sharedKey) {
        return decryptShared(null, ciphertext, nonce, sharedKey);
    }

    /**
     * As above, but result BytesStore is passed in first arg
     *
     * @param result
     *            - the BytesStore for the cleartext result remaining params as above
     * @param ciphertext
     *            - the ciphertext message
     * @param nonce
     *            - one-off tag associated with this message exchange. Public
     * @param sharedKey
     *            - the shared key formed from sender's public and recipient's private key
     * @return - the cleartext BytesStore (echoes arg1)
     */
    public static BytesStore decryptShared(@Nullable BytesStore result, @NotNull BytesStore ciphertext, Nonce nonce, SharedKey sharedKey) {
        return decryptShared(result, ciphertext, nonce.store, sharedKey.store);
    }

    /**
     * Underlying decryptShared call taking explicit BytesStores Where possible the strongly-typed versions above should be preferred
     *
     * @param result
     *            - the BytesStore for the cleartext result remaining params as above
     * @param ciphertext
     *            - the ciphertext message
     * @param nonce
     *            - one-off tag associated with this message exchange. Public
     * @param sharedKey
     *            - the shared key formed from sender's public and recipient's private key
     * @return - the cleartext BytesStore (echoes arg1)
     */
    public static BytesStore decryptShared(@Nullable BytesStore result, @NotNull BytesStore ciphertext, BytesStore nonce, BytesStore sharedKey) {
        if (sharedKey == null)
            throw new RuntimeException("Decryption failed. Shared key not available.");

        long length = ciphertext.readRemaining();
        long resultLength = length - CRYPTO_BOX_MACBYTES;
        result = Sodium.Util.setSize(result, resultLength);

        checkValid(
                SODIUM.crypto_box_open_easy_afternm(result.addressForWrite(0), ciphertext.addressForRead(ciphertext.readPosition()), length,
                        nonce.addressForRead(nonce.readPosition()), sharedKey.addressForRead(sharedKey.readPosition())),
                "Decryption failed. Ciphertext failed verification");

        return result;
    }

    /**
     * Helper class to wrap Nonce creation and re-use A nonce should only be used for a single message exchange, then refreshed Refresh
     * either by calling next() or stir() depending on the use case - next increments the nonce by 1 in a deterministic fashion (eg for
     * ordered message exchange) - stir fully randomises the nonce again Explicitly named static methods are provided to help avoid mistakes
     * from calling the wrong constructor overload
     */
    public static class Nonce {
        public final BytesStore store;

        private Nonce(BytesStore store) {
            this.store = Sodium.Util.setSize(store, CRYPTO_BOX_NONCEBYTES);
            SODIUM.randombytes_buf(this.store.addressForWrite(0), CRYPTO_BOX_NONCEBYTES);
        }

        private Nonce(BytesStore store, long id) {
            BytesStore seed = Bytes.allocateDirect(RANDOMBYTES_SEEDBYTES);
            seed.writeLong(0, id);

            this.store = Sodium.Util.setSize(store, CRYPTO_BOX_NONCEBYTES);
            SODIUM.randombytes_buf_deterministic(this.store.addressForWrite(0), CRYPTO_BOX_NONCEBYTES, seed.addressForWrite(0));
        }

        private Nonce(BytesStore store, BytesStore seed) {
            seed = Sodium.Util.setSize(seed, RANDOMBYTES_SEEDBYTES);
            this.store = Sodium.Util.setSize(store, CRYPTO_BOX_NONCEBYTES);
            SODIUM.randombytes_buf_deterministic(this.store.addressForWrite(0), CRYPTO_BOX_NONCEBYTES, seed.addressForWrite(0));
        }

        /**
         * Generate random nonce. Optionally pass in the underlying BytesStore, else one is created
         *
         * @return - a random nonce
         */
        public static Nonce generate() {
            return generate(null);
        }

        public static Nonce generate(BytesStore store) {
            return new Nonce(store);
        }

        /**
         * /** Generate deterministic nonce from simple long id (which only uses 8 out of 32 seed bytes) Optionally pass in the underlying
         * BytesStore, else one is created
         *
         * @param id - the seed value (2^64 options_
         * @return - a deterministic nonce
         */
        public static Nonce deterministic(long id) {
            return deterministic(null, id);
        }

        public static Nonce deterministic(BytesStore store, long id) {
            return new Nonce(store, id);
        }

        /**
         * Generate deterministic nonce from BytesStore accessing full 32 seed bytes Optionally pass in the underlying BytesStore, else one
         * is created
         *
         * @param seed
         *            - seed bytes, which should be at least 32 bytes long
         * @return - a deterministic nonce
         */
        public static Nonce deterministic(BytesStore seed) {
            return deterministic(null, seed);
        }

        public static Nonce deterministic(BytesStore store, BytesStore seed) {
            return new Nonce(store, seed);
        }

        /**
         * Refresh this nonce for reuse for another message with the same key pair by incrementing value by 1
         */
        public void next() {
            SODIUM.sodium_increment(store.addressForWrite(0), CRYPTO_BOX_NONCEBYTES);
        }

        /**
         * Refresh this nonce for reuse for another message with the same key pair by randomising
         */
        public void stir() {
            SODIUM.randombytes_buf(this.store.addressForWrite(0), CRYPTO_BOX_NONCEBYTES);
        }

        /**
         * Get the address of this nonce (only needed if using the explicit low-level interface)
         *
         * @return - the start address of the underlying memory
         */
        public long address() {
            return store.addressForRead(0);
        }
    }

    /**
     * Helper class to manage the public part of a KeyPair A PublicKey is created internally as part of a KeyPair, and provides a
     * strongly-typed wrapper over the underlying BytesStore
     */
    public static class PublicKey {
        public final BytesStore store;

        private PublicKey() {
            this.store = Bytes.allocateDirect(CRYPTO_BOX_PUBLICKEYBYTES);
            ((Bytes) store).readLimit(CRYPTO_BOX_PUBLICKEYBYTES);
        }

        public long address() {
            return store.addressForRead(0);
        }
    }

    /**
     * Helper class to manage the secret part of a KeyPair A SecretKey is created internally as part of a KeyPair, and provides a
     * strongly-typed wrapper over the underlying BytesStore
     */
    public static class SecretKey {
        public final BytesStore store;

        private SecretKey() {
            this.store = Bytes.allocateDirect(CRYPTO_BOX_SECRETKEYBYTES);
            ((Bytes) store).readLimit(CRYPTO_BOX_SECRETKEYBYTES);
        }

        public long address() {
            return store.addressForRead(0);
        }

        /**
         * safely wipe the memory backing this key when finished
         */
        public void wipe() {
            SODIUM.sodium_memzero(address(), CRYPTO_BOX_SECRETKEYBYTES);
        }
    }

    /**
     * Helper class to handle shared key corresponding to given key pair (or parts of) A shared key can be used when multiple messages are
     * being exchanged between the same sender/receiver This avoids the same shared key being deduced from the sender/receiver key pair on
     * every message, resulting in significantly better speeds
     */
    public static class SharedKey {
        public final BytesStore store;

        private SharedKey() {
            this.store = Bytes.allocateDirect(CRYPTO_BOX_BEFORENMBYTES);
            ((Bytes) store).readLimit(CRYPTO_BOX_BEFORENMBYTES);
        }

        /**
         * Precalculate the shared secret key given the public and private part of separate keys This can be used to substantially improve
         * performance when a given sender/receiver exchange multiple messages NOTE: intentionally takes distinct public and private keys
         * rather than a single KeyPair instance as the key components will normally be complementary parts from two different KeyPairs
         *
         * @param publicKey
         *            - the remote side's public key
         * @param secretKey
         *            - own secret key
         * @return - the shared secret key for message exchange
         */
        public static SharedKey precalc(PublicKey publicKey, SecretKey secretKey) {
            SharedKey shared = new SharedKey();
            SODIUM.crypto_box_beforenm(shared.address(), publicKey.address(), secretKey.address());

            return shared;
        }

        public static SharedKey precalc(KeyPair alice, KeyPair bob) {
            // choose public key from one pair, secret key from the other (symmetrical - doesn't matter which way round)
            return precalc(alice.publicKey, bob.secretKey);
        }

        public long address() {
            return store.addressForRead(0);
        }

        /**
         * safely wipe the memory backing this key when finished
         */
        public void wipe() {
            SODIUM.sodium_memzero(address(), CRYPTO_BOX_BEFORENMBYTES);
        }
    }

    /**
     * Helper class to handle KeyPair creation Explicitly named static methods are provided to help avoid mistakes from calling the wrong
     * constructor overload Constructors in turn are made private
     */
    public static class KeyPair {
        public final PublicKey publicKey;
        public final SecretKey secretKey;

        private KeyPair() {
            this.secretKey = new SecretKey();
            this.publicKey = new PublicKey();

            SODIUM.crypto_box_keypair(publicKey.address(), secretKey.address());
        }

        private KeyPair(BytesStore seed) {
            this.secretKey = new SecretKey();
            this.publicKey = new PublicKey();

            seed = Sodium.Util.setSize(seed, CRYPTO_BOX_SEEDBYTES);
            SODIUM.crypto_box_seed_keypair(publicKey.address(), secretKey.address(), seed.addressForWrite(0));
        }

        /**
         * Returns a new generated random public/private key pair.
         *
         * @return a new generated random public/private key pair
         */
        public static KeyPair generate() {
            return new KeyPair();
        }

        /**
         * Returns a new generated deterministic public/private key pair from simple long id (which only uses 8 out of 32 seed bytes)
         *
         * @param id
         *            - deterministic seed
         * @return a new generated deterministic public/private key pair from simple long id (which only uses 8 out of 32 seed bytes)
         */
        public static KeyPair deterministic(long id) {
            BytesStore seed = Bytes.allocateDirect(CRYPTO_BOX_SEEDBYTES);
            seed.writeLong(0, id);
            return deterministic(seed);
        }

        /**
         * Returns a new generated deterministic public/private key pair from BytesStore accessing full 32 seed bytes
         *
         * @param seed
         *            - deterministic BytesStore seed, which should be at least 32 bytes
         * @return a new generated deterministic public/private key pair from BytesStore accessing full 32 seed bytes
         */
        public static KeyPair deterministic(BytesStore seed) {
            return new KeyPair(seed);
        }

        /**
         * Safely wipes the memory backing the secret part of this key pair when finished.
         */
        public void wipe() {
            secretKey.wipe();
        }
    }
}
