package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.core.Maths;

public enum SHA2 {
    ;
    static final int CRYPTO_HASH_SHA256_BYTES = 32;

    static final int CRYPTO_HASH_SHA512_BYTES = 64;

    public static void sha256(Bytes<?> hash256, BytesStore message) {
        long wp = hash256.writePosition();
        hash256.ensureCapacity(wp + CRYPTO_HASH_SHA256_BYTES);
        Sodium.SODIUM.crypto_hash_sha256(
                hash256.addressForWrite(wp),
                message.addressForRead(message.readPosition()),
                Maths.toUInt31(message.readRemaining()));
    }

    public static void sha512(Bytes<?> hash512, BytesStore message) {
        long wp = hash512.writePosition();
        hash512.ensureCapacity(wp + CRYPTO_HASH_SHA512_BYTES);
        Sodium.SODIUM.crypto_hash_sha512(
                hash512.addressForWrite(wp),
                message.addressForRead(message.readPosition()),
                Maths.toUInt31(message.readRemaining()));
    }
}
