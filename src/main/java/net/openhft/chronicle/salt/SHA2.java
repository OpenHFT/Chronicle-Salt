package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.core.Maths;

import static net.openhft.chronicle.salt.Sodium.*;

public enum SHA2 {
    ;
    static final int HASH_SHA256_BYTES = 32;
    static final int HASH_SHA512_BYTES = 64;

    /**
     * Generate sha256 hash for a given message
     *
     * @param message - the message to hash
     * @return - the sha256 hash
     */
    public static BytesStore sha256(BytesStore message) {
        return sha256(null, message);
    }

    /**
     * Generate hash for a given message
     *
     * @param result  - the BytesStore to hold the result
     * @param message - the message to hash
     * @return - the sha256 hash
     */
    public static BytesStore sha256(BytesStore result, BytesStore message) {
        result = Sodium.Util.setSize(result, HASH_SHA256_BYTES);
        checkValid(Sodium.SODIUM.crypto_hash_sha256(result.addressForWrite(0), message.addressForRead(message.readPosition()),
                Maths.toUInt31(message.readRemaining())), "couldn't SHA256");
        return result;
    }

    /**
     * Append the sha256 hash of a message to a given Bytes handle
     *
     * @param hash256 - the Bytes handle onto which the sha256 hash is appended
     * @param message - the message to hash
     */
    public static void appendSha256(Bytes<?> hash256, BytesStore<?, ?> message) {
        long wp = hash256.writePosition();
        hash256.ensureCapacity(wp + HASH_SHA256_BYTES);
        checkValid(Sodium.SODIUM.crypto_hash_sha256(hash256.addressForWrite(wp), message.addressForRead(message.readPosition()),
                Maths.toUInt31(message.readRemaining())), "couldn't SHA256");
        hash256.writeSkip(HASH_SHA256_BYTES);
    }

    /**
     * Generate sha512 hash for a given message
     *
     * @param message - the message to hash
     * @return - the sha256 hash
     */
    public static BytesStore sha512(BytesStore message) {
        return sha512(null, message);
    }

    /**
     * Generate sha512 hash for a given message
     *
     * @param result  - the BytesStore to hold the result
     * @param message - the message to hash
     * @return - the sha512 hash
     */
    public static BytesStore sha512(BytesStore result, BytesStore message) {
        result = Sodium.Util.setSize(result, HASH_SHA512_BYTES);
        checkValid(Sodium.SODIUM.crypto_hash_sha512(result.addressForWrite(0), message.addressForRead(message.readPosition()),
                Maths.toUInt31(message.readRemaining())), "Couldn't SHA512");
        return result;
    }

    /**
     * Append the sha512 hash of a message to a given Bytes handle
     *
     * @param hash512 - the Bytes handle onto which the sha512 hash is appended
     * @param message - the message to hash
     */
    public static void appendSha512(Bytes<?> hash512, BytesStore<?, ?> message) {
        long wp = hash512.writePosition();
        hash512.ensureCapacity(wp + HASH_SHA512_BYTES);
        checkValid(Sodium.SODIUM.crypto_hash_sha512(hash512.addressForWrite(wp), message.addressForRead(message.readPosition()),
                Maths.toUInt31(message.readRemaining())), "Couldn't SHA512");
        hash512.writeSkip(HASH_SHA512_BYTES);
    }

    /**
     * Wrapper for SHA-256 signing multi-part messages composed of a sequence of arbitrarily-sized chunks
     */
    public static class MultiPartSHA256 {
        public final BytesStore state;

        /**
         * Initialise a wrapper for a single multi-part message exchange
         */
        public MultiPartSHA256() {
            this.state = Bytes.allocateDirect(SIZEOF_CRYPTO_HASH_SHA256_STATE);
            ((Bytes) state).readLimit(SIZEOF_CRYPTO_HASH_SHA256_STATE);

            Sodium.SODIUM.crypto_hash_sha256_init(state.addressForRead(0));
        }

        public void reset() {
            Sodium.SODIUM.crypto_hash_sha256_init(state.addressForRead(0));
        }

        /**
         * Add a part to this multi-part hash
         *
         * @param message - the message to add
         */
        public void add(BytesStore message) {
            checkValid(Sodium.SODIUM.crypto_hash_sha256_update(state.addressForRead(0), message.addressForRead(message.readPosition()),
                    message.readRemaining()), "Failed to add to multi-part message");
        }

        /**
         * Generate the single hash for the collection of messages
         *
         * @return - the single hash
         */
        public BytesStore hash() {
            return hash(null);
        }

        public BytesStore hash(BytesStore result) {
            result = Sodium.Util.setSize(result, HASH_SHA256_BYTES);
            checkValid(Sodium.SODIUM.crypto_hash_sha256_final(state.addressForRead(0), result.addressForWrite(0)), "Multi-part SHA256 failed");

            return result;
        }
    }

    /**
     * Wrapper for SHA-512 signing multi-part messages composed of a sequence of arbitrarily-sized chunks
     */
    public static class MultiPartSHA512 {
        public final BytesStore state;

        /**
         * Initialise a wrapper for a single multi-part message exchange
         */
        public MultiPartSHA512() {
            this.state = Bytes.allocateDirect(SIZEOF_CRYPTO_HASH_SHA512_STATE);
            ((Bytes) state).readLimit(SIZEOF_CRYPTO_HASH_SHA512_STATE);

            Sodium.SODIUM.crypto_hash_sha512_init(state.addressForRead(0));
        }

        public void reset() {
            Sodium.SODIUM.crypto_hash_sha512_init(state.addressForRead(0));
        }

        /**
         * Add a part to this multi-part hash
         *
         * @param message - the message to add
         */
        public void add(BytesStore message) {
            checkValid(Sodium.SODIUM.crypto_hash_sha512_update(state.addressForRead(0), message.addressForRead(message.readPosition()),
                    message.readRemaining()), "Failed to add to multi-part message");
        }

        /**
         * Generate the single hash for the collection of messages
         *
         * @return - the single hash
         */
        public BytesStore hash() {
            return hash(null);
        }

        public BytesStore hash(BytesStore result) {
            result = Sodium.Util.setSize(result, HASH_SHA512_BYTES);
            checkValid(Sodium.SODIUM.crypto_hash_sha512_final(state.addressForRead(0), result.addressForWrite(0)), "Multi-part SHA512 failed");

            return result;
        }
    }

}
