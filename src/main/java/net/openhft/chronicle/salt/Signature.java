package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.core.annotation.NotNull;
import net.openhft.chronicle.core.annotation.Nullable;

import static net.openhft.chronicle.salt.Sodium.*;

public enum Signature {
    ;

    /**
     * Sign a message given a secret key
     * @param message - the message to sign
     * @param secretKey - the signer's private key
     * @return - the signed message BytesStore
     */
    public static BytesStore sign(BytesStore message, SecretKey secretKey) {
        return sign( null, message, secretKey);
    }

    /**
     * As above, but result BytesStore is passed in first arg
     * @param result - the ByteStore for the signed message
     * remaining params as above
     * @return - the signed message BytesStore (echoes arg1)
     */
    public static BytesStore sign(BytesStore result, BytesStore message, SecretKey secretKey) {
        return sign( result, message, secretKey.store );
    }

    /**
     * Underlying sign call taking explicit BytesStores
     * Where possible the strongly-typed versions above should be preferred
     */
    public static BytesStore sign(BytesStore result, BytesStore message, BytesStore secretKey) {
        if (secretKey == null)
            throw new RuntimeException("Sign failed. Secret key not available.");

        long length = message.readRemaining();
        long resultLength = length + CRYPTO_SIGN_BYTES;
        result = Sodium.Util.setSize(result, resultLength);

        checkValid(SODIUM.crypto_sign(result.addressForWrite(0), 0, message.addressForRead(message.readPosition()), length,
                   secretKey.addressForRead(secretKey.readPosition())), "Signing failed");

        return result;
    }

    /**
     * Verify a signed message using the signer's public key
     * @param message - the signed message
     * @param publicKey - the signer's public key
     * @return - the unsigned message
     */
    @NotNull
    public static BytesStore verify(@NotNull BytesStore message, PublicKey publicKey) {
        return verify( null, message, publicKey );
    }

    /**
     * As above, but result BytesStore is passed in first arg
     * @param result - the BytesStore for the cleartext result
     * remaining params as above
     * @return - the cleartext BytesStore (echoes arg1)
     */
    public static BytesStore verify(@Nullable BytesStore result, @NotNull BytesStore message, PublicKey publicKey) {
        return verify( result, message, publicKey.store );
    }

    /**
     * Underlying decrypt call taking explicit BytesStores
     * Where possible the strongly-typed versions above should be preferred
     */
    public static BytesStore verify(@Nullable BytesStore result, @NotNull BytesStore message, BytesStore publicKey) {
        if (publicKey == null)
            throw new RuntimeException("Decryption failed. Public key not available.");

        long length = message.readRemaining();
        long resultLength = length - CRYPTO_SIGN_BYTES;
        result = Sodium.Util.setSize(result, resultLength);

        checkValid(SODIUM.crypto_sign_open(result.addressForWrite(0), 0, message.addressForRead(message.readPosition()), length,
                publicKey.addressForRead(publicKey.readPosition())), "Signature verification failed");

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
            this.store = Bytes.allocateDirect(CRYPTO_SIGN_PUBLICKEYBYTES);
            ((Bytes) store).readLimit(CRYPTO_SIGN_PUBLICKEYBYTES);
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
            this.store = Bytes.allocateDirect(CRYPTO_SIGN_SECRETKEYBYTES);
            ((Bytes) store).readLimit(CRYPTO_SIGN_SECRETKEYBYTES);
        }

        public long address()
        {
            return store.addressForRead(0);
        }

        /**
         * safely wipe the memory backing this key when finished
         */
        public void wipe() { SODIUM.sodium_memzero( address(), CRYPTO_SIGN_SECRETKEYBYTES); }
    }

    /**
     * Helper class to handle KeyPair creation
     * Explicitly named static methods are provided to help avoid mistakes from calling the wrong constructor overload
     * Constructors in turn are made private
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

            SODIUM.crypto_sign_keypair(publicKey.address(), secretKey.address());
        }

        /**
         * Generate deterministic public/private key pair from simple long id (which only uses 8 out of 32 seed bytes)
         * @param id - deterministic seed
         */
        public static KeyPair deterministic( long id )
        {
            BytesStore seed = Bytes.allocateDirect(CRYPTO_SIGN_SEEDBYTES);
            seed.writeLong(0, id );
            return deterministic( seed );
        }

        /**
         * Generate deterministic public/private key pair from BytesStore accessing full 32 seed bytes
         * @param seed - deterministic BytesStore seed, which should be at least 32 bytes
         */
        public static KeyPair deterministic( BytesStore seed )
        {
            return new KeyPair(seed);
        }

        private KeyPair(BytesStore seed) {
            this.secretKey = new SecretKey();
            this.publicKey = new PublicKey();

            seed = Sodium.Util.setSize(seed, CRYPTO_SIGN_SEEDBYTES);
            SODIUM.crypto_sign_seed_keypair(publicKey.address(),secretKey.address(),seed.addressForWrite(0));
        }

        /**
         * safely wipe the memory backing the secret part of this key pair when finished
         */
        public void wipe() { secretKey.wipe(); }
    }
}
