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

import jnr.ffi.byref.LongLongByReference;
import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;

import static net.openhft.chronicle.salt.Sodium.SODIUM;
import static net.openhft.chronicle.salt.Sodium.checkValid;

public enum Ed25519 {
    ; // none

    public static final int PRIVATE_KEY_LENGTH = 32;
    public static final int PUBLIC_KEY_LENGTH = 32;
    public static final int SECRET_KEY_LENGTH = PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH;
    public static final int SIGNATURE_LENGTH = 64;
    private static final ThreadLocal<LocalEd25519> CACHED_CRYPTO = ThreadLocal.withInitial(LocalEd25519::new);

    public static Bytes<Void> allocatePublicKey() {
        return Bytes.allocateDirect(PUBLIC_KEY_LENGTH);
    }

    public static Bytes<Void> allocatePrivateKey() {
        return Bytes.allocateDirect(PRIVATE_KEY_LENGTH);
    }

    public static Bytes<Void> allocateSecretKey() {
        return Bytes.allocateDirect(SECRET_KEY_LENGTH);
    }

    public static Bytes<Void> generateRandomBytes(int length) {
        Bytes<Void> bytes = Bytes.allocateElasticDirect(length);
        SODIUM.randombytes(bytes.addressForWrite(0), length);
        bytes.readPositionRemaining(0, length);
        return bytes;
    }

    public static void privateToPublicAndSecret(Bytes<?> publicKey, Bytes<?> secretKey, BytesStore<?, ?> privateKey) {
        if (privateKey.readRemaining() != PRIVATE_KEY_LENGTH) {
            throw new IllegalArgumentException("privateKey");
        }
        assert privateKey.refCount() > 0;
        assert secretKey.refCount() > 0;
        assert publicKey.refCount() > 0;
        publicKey.ensureCapacity(publicKey.writePosition() + PUBLIC_KEY_LENGTH);
        secretKey.ensureCapacity(secretKey.writePosition() + SECRET_KEY_LENGTH);
        assert privateKey.isDirectMemory();
        assert secretKey.isDirectMemory();
        assert publicKey.isDirectMemory();

        long publicKeyAddress = publicKey.addressForWrite(publicKey.writePosition());
        long secretKeyAddress = secretKey.addressForWrite(secretKey.writePosition());
        long seed = privateKey.addressForRead(privateKey.readPosition());
        SODIUM.crypto_sign_ed25519_seed_keypair(publicKeyAddress, secretKeyAddress, seed);
        publicKey.readPositionRemaining(publicKey.writePosition(), PUBLIC_KEY_LENGTH);
        secretKey.readPositionRemaining(secretKey.writePosition(), SECRET_KEY_LENGTH);
    }

    public static void sign(BytesStore sigAndMsg, BytesStore<?, ?> secretKey) {
        assert sigAndMsg.refCount() > 0;
        assert secretKey.refCount() > 0;
        assert sigAndMsg.isDirectMemory();
        assert secretKey.isDirectMemory();

        if (secretKey.readRemaining() != SECRET_KEY_LENGTH) {
            throw new IllegalArgumentException("Must be a secretKey");
        }
        CACHED_CRYPTO.get().sign(sigAndMsg, secretKey);
    }

    public static void sign(Bytes<?> signature, BytesStore<?, ?> message, BytesStore<?, ?> secretKey) {
        signature.ensureCapacity(signature.writePosition() + SIGNATURE_LENGTH + message.readRemaining());
        assert signature.refCount() > 0;
        assert message.refCount() > 0;
        assert secretKey.refCount() > 0;
        assert signature.isDirectMemory();
        assert message.isDirectMemory();
        assert secretKey.isDirectMemory();

        if (secretKey.readRemaining() != SECRET_KEY_LENGTH) {
            throw new IllegalArgumentException("Must be a secretKey");
        }
        CACHED_CRYPTO.get().sign(signature, message, secretKey);
    }

    public static void sign(BytesStore<?, ?> sigAndMsg, long signatureOffset, long messageOffset, int messageLength, BytesStore<?, ?> secretKey) {
        long maxLength = Math.max(signatureOffset + Ed25519.SIGNATURE_LENGTH, messageOffset + messageLength);
        if (sigAndMsg instanceof Bytes) {
            final Bytes<?> bytes = (Bytes) sigAndMsg;
            bytes.ensureCapacity(maxLength);
            if (sigAndMsg.readLimit() < maxLength)
                bytes.writePosition(maxLength);
        } else if (sigAndMsg.writeLimit() < maxLength) {
            throw new IllegalArgumentException();
        }
        assert sigAndMsg.refCount() > 0;
        assert secretKey.refCount() > 0;
        assert sigAndMsg.isDirectMemory();
        assert secretKey.isDirectMemory();

        if (secretKey.readRemaining() != SECRET_KEY_LENGTH) {
            throw new IllegalArgumentException("Must be a secretKey");
        }
        CACHED_CRYPTO.get().sign_detached(sigAndMsg, signatureOffset, messageOffset, messageLength, secretKey);
    }

    public static boolean verify(BytesStore<?, ?> sigAndMsg, BytesStore<?, ?> publicKey) {
        assert sigAndMsg.refCount() > 0;
        assert publicKey.refCount() > 0;
        assert sigAndMsg.isDirectMemory();
        assert publicKey.isDirectMemory();

        if (sigAndMsg.readRemaining() < SIGNATURE_LENGTH) {
            throw new IllegalArgumentException("sigAndMsg");
        }
        if (publicKey.readRemaining() != PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("publicKey");
        }
        return CACHED_CRYPTO.get().verify(sigAndMsg, publicKey);
    }

    public static boolean verify(BytesStore<?, ?> sigAndMsg, long signatureOffset, long messageOffset, int messageLength,
            BytesStore<?, ?> publicKey) {
        long maxLength = Math.max(signatureOffset + Ed25519.SIGNATURE_LENGTH, messageOffset + messageLength);
        if (sigAndMsg.writeLimit() < maxLength)
            throw new IllegalArgumentException();

        assert sigAndMsg.refCount() > 0;
        assert publicKey.refCount() > 0;
        assert sigAndMsg.isDirectMemory();
        assert publicKey.isDirectMemory();

        if (sigAndMsg.readRemaining() < SIGNATURE_LENGTH) {
            throw new IllegalArgumentException("sigAndMsg");
        }
        if (publicKey.readRemaining() != PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("publicKey");
        }
        return CACHED_CRYPTO.get().verify_detached(sigAndMsg, signatureOffset, messageOffset, messageLength, publicKey);
    }

    public static void generatePrivateKey(Bytes<?> privateKey) {
        assert privateKey.refCount() > 0;
        privateKey.ensureCapacity(PRIVATE_KEY_LENGTH);
        assert privateKey.isDirectMemory();
        long address = privateKey.addressForWrite(0);
        SODIUM.randombytes(address, PRIVATE_KEY_LENGTH);
        privateKey.readPositionRemaining(0, PRIVATE_KEY_LENGTH);
    }

    public static Bytes<Void> generatePrivateKey() {
        Bytes<Void> privateKey = Bytes.allocateDirect(PRIVATE_KEY_LENGTH);
        generatePrivateKey(privateKey);
        return privateKey;
    }

    public static void generatePublicAndSecretKey(Bytes<Void> publicKey, Bytes<Void> secretKey) {
        Bytes<Void> privateKey = Bytes.allocateDirect(PRIVATE_KEY_LENGTH);

        try {
            generatePrivateKey(privateKey);
            privateToPublicAndSecret(publicKey, secretKey, privateKey);

        } finally {
            privateKey.releaseLast();
        }
    }

    static class LocalEd25519 {

        // Not thread safe or needed.
        @Deprecated final LongLongByReference sigLen = new LongLongByReference(0);
        @Deprecated final Bytes<?> buffer = Bytes.allocateElasticDirect(64); // no idea. Required but doesn't appear to be used.

        void sign(Bytes<?> sigAndMsg, BytesStore<?, ?> message, BytesStore<?, ?> secretKey) {
            int msgLen = Math.toIntExact(message.readRemaining());
            long signatureAddress = sigAndMsg.addressForWrite(sigAndMsg.writePosition());
            long messageAddress = message.addressForRead(message.readPosition());
            long secretKeyAddress = secretKey.addressForRead(secretKey.readPosition());
            checkValid(SODIUM.crypto_sign_ed25519(signatureAddress, sigLen, messageAddress, msgLen, secretKeyAddress), "Unable to sign");
            long bytesToSkip = sigLen.longValue();
            sigAndMsg.writeSkip(bytesToSkip);
        }

        void sign_detached(BytesStore<?, ?> sigAndMsg, long signatureOffset, long messageOffset, int messageLength, BytesStore<?, ?> secretKey) {
            long signatureAddress = sigAndMsg.addressForWrite(signatureOffset);
            long messageAddress = sigAndMsg.addressForRead(messageOffset);
            long secretKeyAddress = secretKey.addressForRead(secretKey.readPosition());
            checkValid(SODIUM.crypto_sign_ed25519_detached(signatureAddress, 0, messageAddress, messageLength, secretKeyAddress), "Unable to sign");
        }

        void sign(BytesStore sigAndMsg, BytesStore<?, ?> secretKey) {
            int msgLen = (int) sigAndMsg.readRemaining() - Ed25519.SIGNATURE_LENGTH;
            long signatureAddress = sigAndMsg.addressForRead(sigAndMsg.readPosition());
            long messageAddress = sigAndMsg.addressForRead(sigAndMsg.readPosition() + SIGNATURE_LENGTH);
            long secretKeyAddress = secretKey.addressForRead(secretKey.readPosition());
            checkValid(SODIUM.crypto_sign_ed25519(signatureAddress, sigLen, messageAddress, msgLen, secretKeyAddress), "Unable to sign");
            assert sigLen.longValue() == sigAndMsg.readRemaining();
        }

        boolean verify(BytesStore<?, ?> sigAndMsg, BytesStore<?, ?> publicKey) {
            int length = sigAndMsg.length();
            buffer.ensureCapacity(length);
            long sigAndMsgAddress = sigAndMsg.addressForRead(sigAndMsg.readPosition());
            long publicKeyAddress = publicKey.addressForRead(publicKey.readLimit() - Ed25519.PUBLIC_KEY_LENGTH);
            int ret = SODIUM.crypto_sign_ed25519_open(0, 0, sigAndMsgAddress, (int) sigAndMsg.readRemaining(), publicKeyAddress);
            return ret == 0;
        }

        boolean verify_detached(BytesStore<?, ?> sigAndMsg, long signatureOffset, long messageOffset, int messageLength, BytesStore<?, ?> publicKey) {
            long signatureAddress = sigAndMsg.addressForRead(signatureOffset);
            long messageAddress = sigAndMsg.addressForRead(messageOffset);
            long publicKeyAddress = publicKey.addressForRead(publicKey.readLimit() - Ed25519.PUBLIC_KEY_LENGTH);
            int ret = SODIUM.crypto_sign_ed25519_verify_detached(signatureAddress, messageAddress, messageLength, publicKeyAddress);
            return ret == 0;
        }
    }

    public static class KeyPair {
        public final Bytes<?> publicKey = Bytes.allocateDirect(PUBLIC_KEY_LENGTH);
        public final Bytes<?> secretKey = Bytes.allocateDirect(SECRET_KEY_LENGTH);

        public KeyPair(long id) {
            Bytes<Void> privateKey = Bytes.allocateDirect(PRIVATE_KEY_LENGTH);
            privateKey.zeroOut(0, PRIVATE_KEY_LENGTH);
            privateKey.writeLong(PRIVATE_KEY_LENGTH - Long.BYTES, id);
            privateKey.writeSkip(PRIVATE_KEY_LENGTH);
            privateToPublicAndSecret(publicKey, secretKey, privateKey);
            privateKey.releaseLast();
        }

        public KeyPair(char ch) {
            Bytes<Void> privateKey = Bytes.allocateDirect(PRIVATE_KEY_LENGTH);
            while (privateKey.writeRemaining() > 0)
                privateKey.append(ch);
            privateToPublicAndSecret(publicKey, secretKey, privateKey);
            privateKey.releaseLast();
        }
    }
}
