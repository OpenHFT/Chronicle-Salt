package net.openhft.chronicle.salt;

import javax.xml.bind.DatatypeConverter;

import jnr.ffi.LibraryLoader;
import jnr.ffi.Platform;
import jnr.ffi.annotations.In;
import jnr.ffi.annotations.Out;
import jnr.ffi.byref.LongLongByReference;
import jnr.ffi.types.u_int64_t;
import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;

public interface Sodium {
	String STANDARD_GROUP_ELEMENT = "0900000000000000000000000000000000000000000000000000000000000000";

	BytesStore<?, ?> SGE_BYTES = Init.fromHex(0, STANDARD_GROUP_ELEMENT);

	int ED25519_PUBLICKEY_BYTES = 32;

	int ED25519_PRIVATEKEY_BYTES = 32;

	int ED25519_SECRETKEY_BYTES = ED25519_PUBLICKEY_BYTES + ED25519_PRIVATEKEY_BYTES;

	Sodium SODIUM = Init.init();

	static void checkValid(int status, String description) {
		if (status != 0) {
			throw new IllegalStateException(description + ", status: " + status);
		}
	}

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

	// verify
	int crypto_sign_ed25519_open(@In long buffer, @Out LongLongByReference bufferLen, @In long sigAndMsg, @In @u_int64_t int sigAndMsgLen,
			@In long publicKey);

	int crypto_scalarmult_curve25519(@In long result, @In long intValue, @In long point);

	enum Init {
		;

		static Sodium init() {
			String libraryName = "sodium";
			if (Platform.getNativePlatform().getOS() == Platform.OS.WINDOWS) {
				libraryName = "libsodium";
			}

			Sodium sodium = LibraryLoader.create(Sodium.class).search("/usr/local/lib").search("/opt/local/lib").search("lib").load(libraryName);

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
