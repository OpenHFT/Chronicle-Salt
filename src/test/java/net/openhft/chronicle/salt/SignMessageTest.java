package net.openhft.chronicle.salt;

import static net.openhft.chronicle.salt.BytesForTest.bytesWithZeros;
import static net.openhft.chronicle.salt.BytesForTest.compare;
import static net.openhft.chronicle.salt.BytesForTest.fromHex;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

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
public class SignMessageTest {
	private static final int SIGNATURE_SIZE = 512 / Byte.SIZE;

	@Parameter(0)
	public Bytes seed;
	@Parameter(1)
	public Bytes message;
	@Parameter(2)
	public Bytes signExpected;
	@Parameter(3)
	public Bytes signedMsg;
	@Parameter(4)
	public String testName;

	@SuppressWarnings("unchecked")
	@Parameters(name = "{4}")
	public static Collection<Object[]> data() throws IOException {
		String[] paramInput = { "test-vectors/rfc-8032.yaml", "test-vectors/python.yaml" };
		ArrayList<Object[]> params = new ArrayList<>();
		for (String paramFile : paramInput) {
			TextWire textWire = new TextWire(BytesUtil.readFile(paramFile));
			List<Map<String, String>> testData = (List<Map<String, String>>) textWire.readMap().get("tests");
			for (Map<String, String> data : testData) {
				Object[] param = new Object[5];
				param[0] = fromHex(data.get("SECRET KEY"));
				param[1] = fromHex(data.get("MESSAGE").toString());
				param[2] = fromHex(data.get("SIGNATURE"));
				param[3] = fromHex(SIGNATURE_SIZE, data.get("MESSAGE").toString());
				param[4] = data.get("NAME");
				params.add(param);
			}
		}
		return params;
	}

	@Test
	public void testSigning() {
		Bytes secretKey = bytesWithZeros(32 * 2);
		Bytes publicKey = bytesWithZeros(32);
		Ed25519.privateToPublicAndSecret(publicKey, secretKey, seed);
		Ed25519.sign(signedMsg, message, secretKey);
		compare(signExpected, signedMsg, SIGNATURE_SIZE);
	}

}
