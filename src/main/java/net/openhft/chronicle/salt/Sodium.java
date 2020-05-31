package net.openhft.chronicle.salt;

import jnr.ffi.LibraryLoader;
import jnr.ffi.Platform;
import jnr.ffi.annotations.In;
import jnr.ffi.annotations.Out;
import jnr.ffi.byref.LongLongByReference;
import jnr.ffi.types.u_int64_t;
import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.bytes.NativeBytesStore;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.xml.bind.DatatypeConverter;

public interface Sodium {
    String STANDARD_GROUP_ELEMENT = "0900000000000000000000000000000000000000000000000000000000000000";

    BytesStore<?, ?> SGE_BYTES = Init.fromHex(0, STANDARD_GROUP_ELEMENT);

    int ED25519_PUBLICKEY_BYTES = 32;

    int ED25519_PRIVATEKEY_BYTES = 32;

    int ED25519_SECRETKEY_BYTES = ED25519_PUBLICKEY_BYTES + ED25519_PRIVATEKEY_BYTES;

    Sodium SODIUM = Init.init();

    int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES = 32;
    int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES = 32;
    int SIZEOF_CRYPTO_HASH_SHA256_STATE = 128; // actual = 104. Add a little headroom
    int SIZEOF_CRYPTO_HASH_SHA512_STATE = 256; // actual = 208. Add a little headroom
    // ---------------------------------------------------------------------
    // Public-key cryptography: Sealed boxes
    int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES = 32;
    int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES = 16;
    int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES = CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES
            - CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES;
    int CRYPTO_BOX_SEALBYTES = CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES + CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES;
    int CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES = 32;
    int CRYPTO_BOX_PUBLICKEYBYTES = CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES;
    int CRYPTO_BOX_SECRETKEYBYTES = CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES;
    int CRYPTO_BOX_MACBYTES = CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES;
    int CRYPTO_BOX_NONCEBYTES = 24;
    int CRYPTO_BOX_SEEDBYTES = 32;
    int RANDOMBYTES_SEEDBYTES = 32;
    int CRYPTO_BOX_BEFORENMBYTES = 32;
    int CRYPTO_SIGN_BYTES = 64;
    int CRYPTO_SIGN_SEEDBYTES = 32;
    int CRYPTO_SIGN_PUBLICKEYBYTES = 32;
    int CRYPTO_SIGN_SECRETKEYBYTES = 64;
    int SIZEOF_CRYPTO_SIGN_STATE = 256; // actual = 208. Add a little headroom

    static void checkValid(int status, String description) throws IllegalStateException {
        if (status != 0) {
            throw new IllegalStateException(description + ", status: " + status);
        }
    }

    int sodium_init(); // must be called only once, single threaded.

    String sodium_version_string();

    void sodium_memzero(@In long address, @In @u_int64_t long size);

    void sodium_increment(@In long buffer, @In @u_int64_t int size);

    void randombytes(@In long buffer, @In @u_int64_t int size);

    void randombytes_buf(@In long buffer, @In @u_int64_t int size);

    void randombytes_buf_deterministic(@In long buffer, @In @u_int64_t int size, @In long seed);

    //// Methods for Ed25519
    // key generation.
    int crypto_box_curve25519xsalsa20poly1305_keypair(@In long publicKey, @In long privateKey);

    // generate a public key from a private one
    int crypto_sign_ed25519_seed_keypair(@In long publicKey, @In long secretKey, @In long seed);

    // sign
    int crypto_sign_ed25519(@In long signature, @Out LongLongByReference sigLen, @In long message, @In @u_int64_t int msgLen, @In long secretKey);

    /// Easy Boxes

    int crypto_scalarmult_curve25519(@In long result, @In long intValue, @In long point);

    int crypto_hash_sha256(@In long buffer, @In long message, @In @u_int64_t int sizeof);

    int crypto_hash_sha256_init(@In long state);

    int crypto_hash_sha256_update(@In long state, @In long in, @In @u_int64_t long inlen);

    int crypto_hash_sha256_final(@In long state, @In long out);

    int crypto_hash_sha512(@In long buffer, @In long message, @In @u_int64_t int sizeof);

    int crypto_hash_sha512_init(@In long state);

    int crypto_hash_sha512_update(@In long state, @In long in, @In @u_int64_t long inlen);

    int crypto_hash_sha512_final(@In long state, @In long out);

    // verify
    int crypto_sign_ed25519_open(@In long buffer, @Out LongLongByReference bufferLen, @In long sigAndMsg, @In @u_int64_t int sigAndMsgLen,
                                 @In long publicKey);

    int crypto_box_seal(@In long ct, @In long message, @In @u_int64_t int length, @In long publicKey);

    int crypto_box_seal_open(@In long message, @In long c, @In @u_int64_t int length, @In long publicKey, @In long privateKey);

    void crypto_box_keypair(@In long publicKey, @In long secretKey);

    void crypto_box_seed_keypair(@In long publicKey, @In long secretKey, @In long seed);

    int crypto_box_beforenm(@In long shared, @In long publicKey, @In long secretKey);

    int crypto_box_easy(@In long c, @In long m, @In long mlen, @In long n, @In long pk, @In long sk);

    int crypto_box_easy_afternm(@In long c, @In long m, @In long mlen, @In long n, @In long sharedkey);

    int crypto_box_open_easy(@In long m, @In long c, @In long clen, @In long n, @In long pk, @In long sk);

    int crypto_box_open_easy_afternm(@In long c, @In long m, @In long mlen, @In long n, @In long sharedkey);

    int crypto_sign_keypair(@In long pl, @In long sk);

    int crypto_sign_seed_keypair(@In long pk, @In long sk, @In long seed);

    int crypto_sign(@In long sm, @In long smlen, @In long m, @In long mlen, @In long sk);

    int crypto_sign_open(@In long m, @In long mlen, @In long sm, @In long smlen, @In long pk);

    int crypto_sign_init(@In long state);

    int crypto_sign_update(@In long state, @In long m, @In long mlen);

    int crypto_sign_final_create(@In long state, @In long sig, @In long siglen, @In long sk);

    int crypto_sign_final_verify(@In long state, @In long sig, @In long pk);

    int crypto_sign_ed25519_sk_to_seed(@In long seed, @In long sk);

    int crypto_sign_ed25519_sk_to_pk(@In long pk, @In long sk);

    enum Init {
        ;

        static Sodium init() {
            String libraryName = "sodium";
            if (Platform.getNativePlatform().getOS() == Platform.OS.WINDOWS) {
                libraryName = "libsodium";
            }

            Sodium sodium = null;
            try {
                sodium = LibraryLoader.create(Sodium.class).search("lib").search("/usr/local/lib").search("/opt/local/lib").load(libraryName);

            } catch (Error e) {
                if (Platform.getNativePlatform().getOS() == Platform.OS.WINDOWS)
                    System.err.println("Unable to load libsodium, make sure the Visual C++ Downloadable is installed\n"
                            + "https://support.microsoft.com/en-gb/help/2977003/the-latest-supported-visual-c-downloads");
                throw e;
            }

            checkValid(sodium.sodium_init(), "sodium_init()");
            return sodium;
        }

        static Bytes<?> fromHex(int padding, String s) {
            byte[] byteArr = DatatypeConverter.parseHexBinary(s);
            Bytes<?> bytes = Bytes.allocateDirect(padding + byteArr.length);
            if (padding > 0) {
                bytes.zeroOut(0, padding);
                bytes.writePosition(padding);
            }
            bytes.write(byteArr);
            return bytes;
        }
    }

    enum Util {
        ;

        @NotNull
        public static BytesStore setSize(@Nullable BytesStore bs, long size) {
            if (bs == null) {
                return NativeBytesStore.nativeStoreWithFixedCapacity(size);
            }
            assert bs.refCount() > 0;
            if (bs instanceof Bytes) {
                Bytes b = (Bytes) bs;
                b.ensureCapacity(size);
                b.readPositionRemaining(0, size);
                return b;
            } else if (bs.capacity() == size) {
                return bs;
            }
            throw new IllegalArgumentException("Capacity expected " + size + " was " + bs.capacity());
        }
    }
}
