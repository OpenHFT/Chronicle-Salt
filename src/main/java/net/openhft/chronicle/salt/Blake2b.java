/*
 * Copyright 2016-2022 chronicle.software
 *
 *       https://chronicle.software
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.core.Maths;

import static net.openhft.chronicle.salt.Sodium.SIZEOF_CRYPTO_HASH_BLAKE2B_STATE;
import static net.openhft.chronicle.salt.Sodium.checkValid;

public enum Blake2b {
    ; // none
    static final int HASH_BLAKE2B_256_BYTES = 32;
    static final int HASH_BLAKE2B_512_BYTES = 64;

    /**
     * Generate Blake2b hash (256 bits) for a given message
     *
     * @param message
     *            - the message to hash
     * @return - the Blake2b hash
     */
    public static BytesStore hash256(BytesStore message) {
        return hash256(null, message);
    }

    /**
     * Generate Blake2b hash (256 bits) for a given message
     *
     * @param result
     *            - the BytesStore to hold the result
     * @param message
     *            - the message to hash
     * @return - the Blake2b hash
     */
    public static BytesStore hash256(BytesStore result, BytesStore message) {
        result = Sodium.Util.setSize(result, HASH_BLAKE2B_256_BYTES);
        checkValid(Sodium.SODIUM.crypto_generichash(result.addressForWrite(0), HASH_BLAKE2B_256_BYTES, message.addressForRead(message.readPosition()),
                Maths.toUInt31(message.readRemaining()), 0L, 0), "couldn't Blake2b");
        return result;
    }

    /**
     * Append the Blake2b hash (256 bits) of a message to a given Bytes handle
     *
     * @param hashGeneric
     *            - the Bytes handle onto which the Blake2b hash is appended
     * @param message
     *            - the message to hash
     */
    public static void append256(Bytes<?> hashGeneric, BytesStore<?, ?> message) {
        long wp = hashGeneric.writePosition();
        hashGeneric.ensureCapacity(wp + HASH_BLAKE2B_256_BYTES);
        checkValid(Sodium.SODIUM.crypto_generichash(hashGeneric.addressForWrite(wp), HASH_BLAKE2B_256_BYTES,
                message.addressForRead(message.readPosition()), Maths.toUInt31(message.readRemaining()), 0L, 0), "couldn't Blake2b");
        hashGeneric.writeSkip(HASH_BLAKE2B_256_BYTES);
    }

    /**
     * Generate Blake2b hash (512 bits) for a given message
     *
     * @param message
     *            - the message to hash
     * @return - the Blake2b hash
     */
    public static BytesStore hash512(BytesStore message) {
        return hash512(null, message);
    }

    /**
     * Generate Blake2b hash (512 bits) for a given message
     *
     * @param result
     *            - the BytesStore to hold the result
     * @param message
     *            - the message to hash
     * @return - the Blake2b hash
     */
    public static BytesStore hash512(BytesStore result, BytesStore message) {
        result = Sodium.Util.setSize(result, HASH_BLAKE2B_512_BYTES);
        checkValid(Sodium.SODIUM.crypto_generichash(result.addressForWrite(0), HASH_BLAKE2B_512_BYTES, message.addressForRead(message.readPosition()),
                Maths.toUInt31(message.readRemaining()), 0L, 0), "couldn't Blake2b");
        return result;
    }

    /**
     * Append the Blake2b hash (512 bits) of a message to a given Bytes handle
     *
     * @param hashGeneric
     *            - the Bytes handle onto which the Blake2b hash is appended
     * @param message
     *            - the message to hash
     */
    public static void append512(Bytes<?> hashGeneric, BytesStore<?, ?> message) {
        long wp = hashGeneric.writePosition();
        hashGeneric.ensureCapacity(wp + HASH_BLAKE2B_512_BYTES);
        checkValid(Sodium.SODIUM.crypto_generichash(hashGeneric.addressForWrite(wp), HASH_BLAKE2B_512_BYTES,
                message.addressForRead(message.readPosition()), Maths.toUInt31(message.readRemaining()), 0L, 0), "couldn't Blake2b");
        hashGeneric.writeSkip(HASH_BLAKE2B_512_BYTES);
    }

    /**
     * Wrapper for Blake2b signing (256 bits) multi-part messages composed of a sequence of arbitrarily-sized chunks
     */
    public static class MultiPart256 {

        public final BytesStore state;

        /**
         * Initialise a wrapper for a single multi-part message exchange
         */
        public MultiPart256() {
            this.state = Bytes.allocateDirect(SIZEOF_CRYPTO_HASH_BLAKE2B_STATE);
            ((Bytes) state).readLimit(SIZEOF_CRYPTO_HASH_BLAKE2B_STATE);

            Sodium.SODIUM.crypto_generichash_init(state.addressForRead(0), 0L, 0, HASH_BLAKE2B_256_BYTES);
        }

        public void reset() {
            checkValid(Sodium.SODIUM.crypto_generichash_init(state.addressForRead(0), 0L, 0, HASH_BLAKE2B_256_BYTES), "couldn't reset Blake2b");
        }

        /**
         * Add a part to this multi-part hash
         *
         * @param message
         *            - the message to add
         */
        public void add(BytesStore message) {
            checkValid(Sodium.SODIUM.crypto_generichash_update(state.addressForRead(0), message.addressForRead(message.readPosition()),
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
            result = Sodium.Util.setSize(result, HASH_BLAKE2B_256_BYTES);
            checkValid(Sodium.SODIUM.crypto_generichash_final(state.addressForRead(0), result.addressForWrite(0), HASH_BLAKE2B_256_BYTES),
                    "Multi-part Blake2b failed");
            return result;
        }
    }

    /**
     * Wrapper for Blake2b signing (512 bits) multi-part messages composed of a sequence of arbitrarily-sized chunks
     */
    public static class MultiPart512 {

        public final BytesStore state;

        /**
         * Initialise a wrapper for a single multi-part message exchange
         */
        public MultiPart512() {
            this.state = Bytes.allocateDirect(SIZEOF_CRYPTO_HASH_BLAKE2B_STATE);
            ((Bytes) state).readLimit(SIZEOF_CRYPTO_HASH_BLAKE2B_STATE);

            Sodium.SODIUM.crypto_generichash_init(state.addressForRead(0), 0L, 0, HASH_BLAKE2B_512_BYTES);
        }

        public void reset() {
            checkValid(Sodium.SODIUM.crypto_generichash_init(state.addressForRead(0), 0L, 0, HASH_BLAKE2B_512_BYTES), "couldn't reset Blake2b");
        }

        /**
         * Add a part to this multi-part hash
         *
         * @param message
         *            - the message to add
         */
        public void add(BytesStore message) {
            checkValid(Sodium.SODIUM.crypto_generichash_update(state.addressForRead(0), message.addressForRead(message.readPosition()),
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
            result = Sodium.Util.setSize(result, HASH_BLAKE2B_512_BYTES);
            checkValid(Sodium.SODIUM.crypto_generichash_final(state.addressForRead(0), result.addressForWrite(0), HASH_BLAKE2B_512_BYTES),
                    "Multi-part Blake2b failed");
            return result;
        }
    }
}
