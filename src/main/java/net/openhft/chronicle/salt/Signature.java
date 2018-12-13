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

        /**
         * Extract the seed from this secret key
         */
        BytesStore extractSeed()
        {
            return extractSeed(null);
        }

        BytesStore extractSeed( BytesStore seed)
        {
            seed = Sodium.Util.setSize( seed, CRYPTO_SIGN_SEEDBYTES);
            checkValid( SODIUM.crypto_sign_ed25519_sk_to_seed( seed.addressForWrite(0), store.addressForRead(0) )
                    , "Failed to extract seed from signer's secret key" );
            return seed;
        }

        /**
         * Extract the public key from this secret key
         */
        BytesStore extractPublicKey()
        {
            return extractPublicKey(null);
        }

        BytesStore extractPublicKey( BytesStore pk)
        {
            pk = Sodium.Util.setSize( pk, CRYPTO_SIGN_PUBLICKEYBYTES);
            checkValid( SODIUM.crypto_sign_ed25519_sk_to_pk( pk.addressForWrite(0), store.addressForRead(0) ),
                    "Failed to extract public key from signer's secret key" );
            return pk;
        }
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

    /**
     * Wrapper for signing multi-part messages composed of a sequence of arbitrarily-sized chunks
     */
    public static class MultiPart
    {
        public final BytesStore state;

        /**
         * Initialise a wrapper for a single multi-part message exchange
         */
        public MultiPart()
        {
            this.state = Bytes.allocateDirect(SIZEOF_CRYPTO_SIGN_STATE);
            ((Bytes)state).readLimit(SIZEOF_CRYPTO_SIGN_STATE);

            SODIUM.crypto_sign_init( state.addressForRead(0));
        }

        void reset()
        {
            SODIUM.crypto_sign_init( state.addressForRead(0));
        }

        /**
         * Add a part to this multi-part message
         * @param message - the message to add
         */
        public void add( BytesStore message )
        {
            checkValid(SODIUM.crypto_sign_update( state.addressForRead(0),
                                                  message.addressForRead(message.readPosition()),
                                                  message.readRemaining() ),
                    "Failed to add to multi-part message");
        }

        /**
         * Sign the collection of messages with a single overall signature
         * @param sk - the signer's secret key
         * @return - the single signature for the collection of messages
         */
        public BytesStore sign( SecretKey sk )
        {
            return sign( sk.store );
        }

        /**
         * Underlying sign call taking an explicit BytesStore key
         * Where possible the strongly-typed version above should be preferred
         * @param sk - BytesStore corresponding to the signer's secret key
         * @return - the single signature for the collection of messages
         */
        public BytesStore sign( BytesStore sk )
        {
            BytesStore result = Sodium.Util.setSize( null, 	CRYPTO_SIGN_BYTES );
            checkValid(SODIUM.crypto_sign_final_create( state.addressForRead(0),
                                                        result.addressForWrite(0),
                                                        0,
                                                        sk.addressForRead(sk.readPosition()) ),
                    "Multi-part signature failed" );

            return result;
        }

        /**
         * Given a collection of messages, verify that the given signature matches
         * @param signature - the signature to test
         * @param pk - the signer's public key
         */
        public void verify( BytesStore signature, PublicKey pk )
        {
            verify( signature, pk.store );
        }

        /**
         * Underlying verify call taking an explicit BytesStore key
         * Where possible the strongly-typed version above should be preferred
         * @param signature - the signature to test
         * @param pk - the signer's public key
         */
        public void verify( BytesStore signature, BytesStore pk )
        {
            checkValid( SODIUM.crypto_sign_final_verify(state.addressForRead(0),
                                                        signature.addressForRead(signature.readPosition()),
                                                        pk.addressForRead(pk.readPosition())),
                    "Multi-part signature verification failed");
        }
    }
}
