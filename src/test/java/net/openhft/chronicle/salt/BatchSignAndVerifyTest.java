package net.openhft.chronicle.salt;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.junit.AfterClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesUtil;
import net.openhft.chronicle.wire.TextWire;

@RunWith(Parameterized.class)
@SuppressWarnings("rawtypes")
public class BatchSignAndVerifyTest {
	static final BytesForTesting bft = new BytesForTesting();
	private static final int SIGNATURE_SIZE = 512 / Byte.SIZE;
	@Parameter(0)
	public Bytes seed;
	@Parameter(1)
	public Bytes secret;
	@Parameter(2)
	public Bytes publicKey;
	@Parameter(3)
	public Bytes message;
	@Parameter(4)
	public Bytes signExpected;
	@Parameter(5)
	public Bytes signedMsg;
	@Parameter(6)
	public String testName;

	@SuppressWarnings("unchecked")
	@Parameters(name = "{6}")
	public static Collection<Object[]> data() throws IOException {
		String[] paramInput = { "test-vectors/rfc-8032.yaml", "test-vectors/python.yaml" };
		ArrayList<Object[]> params = new ArrayList<>();
		for (String paramFile : paramInput) {
			TextWire textWire = new TextWire(BytesUtil.readFile(paramFile));
			List<Map<String, String>> testData = (List<Map<String, String>>) textWire.readMap().get("tests");
			for (Map<String, String> data : testData) {
				Object[] param = new Object[7];
				Bytes seedOrSecret = bft.fromHex(data.get("SECRET KEY"));
				if (seedOrSecret.readRemaining() == Ed25519.SECRET_KEY_LENGTH) {
					param[1] = seedOrSecret;
				} else {
					param[0] = seedOrSecret;
				}
				param[2] = bft.fromHex(data.get("PUBLIC KEY"));
				String message = data.get("MESSAGE");
				param[3] = bft.fromHex(message);
				String sigAndMsg = data.get("SIGNATURE");
				if (sigAndMsg.length() == 128) {
					sigAndMsg += message;
				}
				param[4] = bft.fromHex(sigAndMsg);
				param[5] = bft.fromHex(SIGNATURE_SIZE, message);
				param[6] = data.get("NAME");
				params.add(param);
			}
		}
		return params;
	}

	@AfterClass
	public static void teardownClass() {
		bft.cleanup();
	}

	@Test
	public void signAndVerify() {
		Bytes secretKey;
		if (secret != null) {
			secretKey = secret;
		} else {
			secretKey = bft.bytesWithZeros(32 * 2);
			Bytes publicKeyBuff = bft.bytesWithZeros(32);
			Ed25519.privateToPublicAndSecret(publicKeyBuff, secretKey, seed);
			assertEquals(publicKeyBuff.toHexString(), publicKey.toHexString());
		}
		Ed25519.sign(signedMsg, message, secretKey);
		assertEquals(signExpected.toHexString(), signedMsg.toHexString());
		signedMsg.readPositionRemaining(0, 64);
		Ed25519.verify(signedMsg, publicKey);
	}
}
