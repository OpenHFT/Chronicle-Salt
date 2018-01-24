package net.openhft.chronicle.salt;

import static net.openhft.chronicle.salt.Sodium.SODIUM;
import static net.openhft.chronicle.salt.Sodium.checkValid;

import jnr.ffi.byref.LongLongByReference;
import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;

public enum Ed25519 {
	;

	private static final String ERR_MEESAGE_PATTERN = "Invalid %s: %d. Must be %d";
	public static final int SECRET_KEY_SIZE = 64;
	public static final int PRIVATE_KEY_SIZE = 32;
	public static final int PUBLIC_KEY_SIZE = 32;
	public static final int SIGNATURE_SIZE = 64;
	public static final int SEED_SIZE = 32;

	private static final ThreadLocal<LocalEd25519> CACHED_CRYPTO = ThreadLocal.withInitial(LocalEd25519::new);

	public static void privateToPublic(Bytes<?> publicKey, Bytes<?> privateKey) {
		Sodium.SODIUM.crypto_scalarmult_curve25519(publicKey.addressForWrite(0), privateKey.addressForRead(0), Sodium.SGE_BYTES.addressForRead(0));
		publicKey.readPositionRemaining(0, PUBLIC_KEY_SIZE);
	}

	public static void privateToPublicAndSecret(Bytes<?> publicKey, Bytes<?> secretKey, BytesStore<?, ?> seed) {
		if (seed.readRemaining() != SEED_SIZE) {
			throw new IllegalArgumentException(String.format(ERR_MEESAGE_PATTERN, "seed size", seed.readRemaining(), SEED_SIZE));
		}
		SODIUM.crypto_sign_ed25519_seed_keypair(publicKey.addressForWrite(0), secretKey.addressForWrite(0), seed.addressForRead(0));
		publicKey.readPositionRemaining(0, PUBLIC_KEY_SIZE);
		secretKey.readPositionRemaining(0, SECRET_KEY_SIZE);
	}

	public static void generateKey(Bytes<?> privateKey, Bytes<?> publicKey) {
		long privateKeyAddr = privateKey.addressForWrite(0);
		long publicKeyAddr = publicKey.addressForWrite(0);
		checkValid(Sodium.SODIUM.crypto_box_curve25519xsalsa20poly1305_keypair(publicKeyAddr, privateKeyAddr), "secret key");
		privateKey.readPositionRemaining(0, PRIVATE_KEY_SIZE);
		publicKey.readPositionRemaining(0, PUBLIC_KEY_SIZE);
	}

	public static void sign(Bytes<?> sigAndMsg, BytesStore<?, ?> message, BytesStore<?, ?> secretKey) {
		if (secretKey.readRemaining() != SECRET_KEY_SIZE) {
			throw new IllegalArgumentException("Must be a secretKey");
		}
		CACHED_CRYPTO.get().sign(sigAndMsg, message, secretKey);
	}

	public static boolean verify(BytesStore<?, ?> sigAndMsg, BytesStore<?, ?> publicKey) {
		if (sigAndMsg.readRemaining() < SIGNATURE_SIZE) {
			throw new IllegalArgumentException("sigAAndMsg");
		}
		if (publicKey.readRemaining() != PUBLIC_KEY_SIZE) {
			throw new IllegalArgumentException("publicKey");
		}
		return CACHED_CRYPTO.get().verify(sigAndMsg, publicKey);
	}

	static class LocalEd25519 {

		final LongLongByReference sigLen = new LongLongByReference(0);
		final Bytes<?> buffer = Bytes.allocateElasticDirect(SIGNATURE_SIZE);

		void sign(Bytes<?> sigAndMsg, BytesStore<?, ?> message, BytesStore<?, ?> secretKey) {
			int msgLen = (int) message.readRemaining();
			checkValid(SODIUM.crypto_sign_ed25519(sigAndMsg.addressForWrite(0), sigLen, message.addressForRead(message.readPosition()), msgLen,
					secretKey.addressForRead(0)), "Unable to sign");
			sigAndMsg.readPositionRemaining(0, sigLen.longValue());
		}

		boolean verify(BytesStore<?, ?> sigAndMsg, BytesStore<?, ?> publicKey) {
			int ret = SODIUM.crypto_sign_ed25519_open(buffer.addressForWrite(0), sigLen, sigAndMsg.addressForRead(sigAndMsg.readPosition()),
					(int) sigAndMsg.readRemaining(), publicKey.addressForRead(publicKey.readPosition()));
			assert sigLen.longValue() <= SIGNATURE_SIZE;
			return ret == 0;
		}
	}
}
