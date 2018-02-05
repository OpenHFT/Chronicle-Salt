package net.openhft.chronicle.salt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

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
public class BatchSignAndVerifyEd25519Test {
    static final BytesForTesting bft = new BytesForTesting();
    @Parameter(0) public String privateOrSecretKey;
    @Parameter(1) public String publicKey;
    @Parameter(2) public String message;
    @Parameter(3) public String signExpected;
    @Parameter(4) public String testName;

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
                param[0] = data.get("SECRET KEY");
                param[1] = data.get("PUBLIC KEY");
                param[2] = data.get("MESSAGE");
                param[3] = data.get("SIGNATURE");
                param[4] = data.get("NAME");
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
        Bytes privateKeyBuffer = null;
        Bytes secretKeyBuffer = null;
        Bytes privateOrSecret = bft.fromHex(privateOrSecretKey);
        if (privateOrSecret.readRemaining() == Ed25519.SECRET_KEY_LENGTH) {
            secretKeyBuffer = privateOrSecret;
        } else {
            privateKeyBuffer = privateOrSecret;
        }

        Bytes publicKeyBuffer = bft.fromHex(publicKey);
        if (secretKeyBuffer == null) {
            secretKeyBuffer = bft.bytesWithZeros(Ed25519.SECRET_KEY_LENGTH);
            Bytes tmpPublicKeyBuffer = bft.bytesWithZeros(Ed25519.PUBLIC_KEY_LENGTH);
            Ed25519.privateToPublicAndSecret(tmpPublicKeyBuffer, secretKeyBuffer, privateKeyBuffer);
            assertEquals(publicKeyBuffer.toHexString(), tmpPublicKeyBuffer.toHexString());
        }
        Bytes messageBuffer = bft.fromHex(message);
        Bytes signExpectedBuffer;
        if (signExpected.length() == 128) {
            signExpectedBuffer = Bytes.wrapForRead(DatatypeConverter.parseHexBinary(signExpected + message));
        } else {
            signExpectedBuffer = Bytes.wrapForRead(DatatypeConverter.parseHexBinary(signExpected));
        }
        Bytes signedMsgBuffer = bft.fromHex(Ed25519.SIGNATURE_LENGTH, message);
        signedMsgBuffer.writePosition(0);
        Ed25519.sign(signedMsgBuffer, messageBuffer, secretKeyBuffer);
        assertEquals(signExpectedBuffer.toHexString(), signedMsgBuffer.toHexString());
        signedMsgBuffer.readPosition(0);
        publicKeyBuffer.readPositionRemaining(0, Ed25519.PUBLIC_KEY_LENGTH);
        assertTrue(Ed25519.verify(signedMsgBuffer, publicKeyBuffer));
    }
}