package net.openhft.chronicle.salt;

import jnr.ffi.LibraryLoader;
import jnr.ffi.Platform;
import jnr.ffi.annotations.In;
import jnr.ffi.annotations.Out;
import jnr.ffi.byref.LongLongByReference;
import jnr.ffi.types.u_int64_t;
import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;

import javax.xml.bind.DatatypeConverter;

public interface Sodium {
    String STANDARD_GROUP_ELEMENT = "0900000000000000000000000000000000000000000000000000000000000000";

    BytesStore<?, ?> SGE_BYTES = Init.fromHex(0, STANDARD_GROUP_ELEMENT);

    int ED25519_PUBLICKEY_BYTES = 32;

    int ED25519_PRIVATEKEY_BYTES = 32;

    int ED25519_SECRETKEY_BYTES = ED25519_PUBLICKEY_BYTES + ED25519_PRIVATEKEY_BYTES;

    Sodium SODIUM = Init.init();

    int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES = 32;

    int sodium_init(); // must be called only once, single threaded.

    String sodium_version_string();

    void randombytes(@In long buffer, @In @u_int64_t int size);

    //// Methods for Ed25519
    // key generation.
    int crypto_box_curve25519xsalsa20poly1305_keypair(@In long publicKey, @In long privateKey);

    // generate a public key from a private one
    int crypto_sign_ed25519_seed_keypair(@In long publicKey, @In long secretKey, @In long seed);

    // sign
    int crypto_sign_ed25519(@In long signature, @Out LongLongByReference sigLen, @In long message, @In @u_int64_t int msgLen, @In long secretKey);

    int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES = 32;

    int crypto_scalarmult_curve25519(@In long result, @In long intValue, @In long point);

    int crypto_hash_sha256(@In long buffer, @In long message, @In @u_int64_t int sizeof);

    int crypto_hash_sha512(@In long buffer, @In long message, @In @u_int64_t int sizeof);

    // ---------------------------------------------------------------------
    // Public-key cryptography: Sealed boxes
    int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES = 32;
    int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES = 16;
    int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES =
            CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES -
                    CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES;
    int CRYPTO_BOX_SEALBYTES =
            CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES +
                    CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES;
    int CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES = 32;

    static void checkValid(int status, String description) throws IllegalStateException {
        if (status != 0) {
            throw new IllegalStateException(description + ", status: " + status);
        }
    }

    // verify
    int crypto_sign_ed25519_open(@In long buffer, @Out LongLongByReference bufferLen, @In long sigAndMsg, @In @u_int64_t int sigAndMsgLen,
                                 @In long publicKey);

    int crypto_box_seal(
            @In long ct, @In long message, @In @u_int64_t int length, @In long publicKey);

    int crypto_box_seal_open(
            @In long message, @In long c, @In @u_int64_t int length, @In long publicKey, @In long privateKey);

    enum Init {
        ;

        static Sodium init() {
            String libraryName = "sodium";
            if (Platform.getNativePlatform().getOS() == Platform.OS.WINDOWS) {
                libraryName = "libsodium";
            }

            Sodium sodium = null;
            try {
                sodium = LibraryLoader.create(Sodium.class)
                        .search("lib")
                        .search("/usr/local/lib")
                        .search("/opt/local/lib")
                        .load(libraryName);

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
}
