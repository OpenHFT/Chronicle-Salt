package net.openhft.chronicle.salt;

import static junit.framework.TestCase.assertTrue;
import static net.openhft.chronicle.salt.Sodium.ED25519_SECRETKEY_BYTES;
import static net.openhft.chronicle.salt.Sodium.SODIUM;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import org.junit.After;
import org.junit.Test;

import jnr.ffi.byref.LongLongByReference;
import net.openhft.chronicle.bytes.Bytes;

@SuppressWarnings("rawtypes")
public class Ed25519Test extends BytesForTesting {

	@After
	public void tearDown() {
		cleanup();
	}

	@Test
	public void secretKey() {
		final String SIGN_PRIVATE = "B18E1D0045995EC3D010C387CCFEB984D783AF8FBB0F40FA7DB126D889F6DADD";
		Bytes privateKey = fromHex(SIGN_PRIVATE);

		Bytes publicKey = bytesWithZeros(32);
		Ed25519.privateToPublic(publicKey, privateKey);

		final String SIGN_PUBLIC = "7AB107CE67B8E8898830C7EE9229AC4AA8B1B33DB2D198DD20D0879E8E521D14";
		Bytes publicKey0 = fromHex(SIGN_PUBLIC);
		assertEquals(publicKey0.toHexString(), publicKey.toHexString());
	}

	@Test
	public void generateKey() {
		Bytes publicKey = bytesWithZeros(32);
		Bytes privateKey = bytesWithZeros(32);
		Ed25519.generateKey(privateKey, publicKey);
		checkZeros(publicKey);
		checkZeros(privateKey);
		checkPseudoRandom(privateKey, 32);
		checkPseudoRandom(publicKey, 32);
	}

	@Test
	public void sign() {
		final String SIGN_PRIVATE = "B18E1D0045995EC3D010C387CCFEB984D783AF8FBB0F40FA7DB126D889F6DADD";
		Bytes privateKey = fromHex(SIGN_PRIVATE);
		Bytes publicKey = bytesWithZeros(32);
		Bytes secretKey = bytesWithZeros(64);
		Ed25519.privateToPublicAndSecret(publicKey, secretKey, privateKey);
		checkZeros(secretKey);
		checkZeros(privateKey);
		Bytes signAndMsg = bytesWithZeros(64 + 32);
		Ed25519.sign(signAndMsg, privateKey, secretKey);
		checkZeros(signAndMsg);
		String SIGN_EXPECTED = "86b4707fadb1ef4613efadd12143cd9dffb2eac329c38923c03f9e315c3dd33bde1ef101137fbc403eb3f3d7ff283155053c667eb65908fe6fcd653eab550e0f";
		Bytes signExpected = fromHex(SIGN_EXPECTED + SIGN_PRIVATE);
		assertEquals(signExpected.toHexString(), signAndMsg.toHexString());
	}

	@Test
	public void signAndVerify() {
		final String SIGN_PRIVATE = "b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd";

		Bytes publicKey = bytesWithZeros(32);
		Bytes secretKey = bytesWithZeros(64);
		Bytes privateKey = fromHex(SIGN_PRIVATE);
		Ed25519.privateToPublicAndSecret(publicKey, secretKey, privateKey);
		assertEquals(32, publicKey.readRemaining());
		assertEquals(64, secretKey.readRemaining());

		Bytes emptyMsg = bytesWithZeros(0);
		Bytes sigAndMsg0 = bytesWithZeros(ED25519_SECRETKEY_BYTES);
		Bytes sigAndMsg = bytesWithZeros(ED25519_SECRETKEY_BYTES);

		Ed25519.sign(sigAndMsg0, emptyMsg, secretKey);

		assertEquals(0, SODIUM.crypto_sign_ed25519(sigAndMsg.addressForWrite(0), new LongLongByReference(0), emptyMsg.addressForRead(0), 0,
				secretKey.addressForRead(0)));

		sigAndMsg.readPositionRemaining(0, 64);

		System.out.println(publicKey.toHexString());
		System.out.println(privateKey.toHexString());
		System.out.println(secretKey.toHexString());
		assertEquals(sigAndMsg.toHexString(), sigAndMsg0.toHexString());
		checkZeros(emptyMsg);
		checkZeros(secretKey);
		checkZeros(sigAndMsg);

		Bytes buffer = bytesWithZeros(ED25519_SECRETKEY_BYTES);

		assertTrue(Ed25519.verify(sigAndMsg, publicKey));
		for (int i = 0; i < sigAndMsg.readRemaining(); i++) {
			byte old = sigAndMsg.readByte(i);
			sigAndMsg.writeByte(i, old ^ 1);
			assertFalse(Ed25519.verify(sigAndMsg, publicKey));
			sigAndMsg.writeByte(i, old);
		}

		assertEquals(0, SODIUM.crypto_sign_ed25519_open(buffer.addressForWrite(0), new LongLongByReference(0), sigAndMsg.addressForRead(0), 0 + 64,
				publicKey.addressForRead(0)));
		sigAndMsg.readPositionRemaining(0, 64);
		System.out.println(sigAndMsg.toHexString());
	}

	@Test(expected = IllegalArgumentException.class)
	public void wrongSeedSize() {
		String SEED = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f683"; // 89
		Bytes seed = fromHex(SEED);
		Bytes secretKey = bytesWithZeros(32 * 2);
		Bytes publicKey = bytesWithZeros(32);
		Ed25519.privateToPublicAndSecret(publicKey, secretKey, seed);

	}

	@Test(expected = IllegalArgumentException.class)
	public void wrongSecretKeySizeToSign() {
		String SIGN_MESSAGE = "916c7d1d268fc0e77c1bef238432573c39be577bbea0998936add2b50a653171"
				+ "ce18a542b0b7f96c1691a3be6031522894a8634183eda38798a0c5d5d79fbd01"
				+ "dd04a8646d71873b77b221998a81922d8105f892316369d5224c9983372d2313"
				+ "c6b1f4556ea26ba49d46e8b561e0fc76633ac9766e68e21fba7edca93c4c7460" + "376d7f3ac22ff372c18f613f2ae2e856af40";
		Bytes secretKey = bytesWithZeros(32 * 1);
		Bytes msg = fromHex(SIGN_MESSAGE);
		Bytes signedMsg = fromHex(Ed25519.SIGANTURE_LENGTH, SIGN_MESSAGE);
		Ed25519.sign(signedMsg, msg, secretKey);
	}

	@Test(expected = IllegalArgumentException.class)
	public void wrongPublicKeySizeToVerify() {
		String SIGN_MESSAGE = "916c7d1d268fc0e77c1bef238432573c39be577bbea0998936add2b50a653171"
				+ "ce18a542b0b7f96c1691a3be6031522894a8634183eda38798a0c5d5d79fbd01"
				+ "dd04a8646d71873b77b221998a81922d8105f892316369d5224c9983372d2313"
				+ "c6b1f4556ea26ba49d46e8b561e0fc76633ac9766e68e21fba7edca93c4c7460" + "376d7f3ac22ff372c18f613f2ae2e856af40";
		Bytes publicKey = bytesWithZeros(32 * 2);
		Bytes sigAndMsg = fromHex(SIGN_MESSAGE);
		Ed25519.verify(sigAndMsg, publicKey);
	}

	@Test(expected = IllegalArgumentException.class)
	public void wrongSignatureSizeToVerify() {
		Bytes publicKey = bytesWithZeros(32);
		Bytes sigAndMsg = bytesWithZeros(32);
		Ed25519.verify(sigAndMsg, publicKey);
	}

	@Test
	public void generateKeys1() {
		Bytes privateKey = Bytes.allocateElasticDirect();
		Ed25519.generatePrivateKey(privateKey);

		Bytes publicKey = Bytes.allocateElasticDirect();
		Ed25519.privateToPublic(publicKey, privateKey);
	}

	@Test
	public void generateKeys2() {
		Bytes publicKey = Bytes.allocateElasticDirect();
		Bytes privateKey = Bytes.allocateElasticDirect();
		Ed25519.generateKey(privateKey, publicKey);
	}

	@Test
	public void generateKeys3() {
		Bytes privateKey = Ed25519.generatePrivateKey();

		Bytes publicKey = Bytes.allocateElasticDirect();
		Bytes secretKey = Bytes.allocateElasticDirect();
		Ed25519.privateToPublicAndSecret(publicKey, secretKey, privateKey);

		System.out.println(privateKey.toHexString());
		System.out.println(publicKey.toHexString());
		System.out.println(secretKey.toHexString());
	}

}