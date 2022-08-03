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

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesUtil;
import net.openhft.chronicle.core.OS;
import net.openhft.chronicle.wire.TextWire;
import org.junit.AfterClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;

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
        String[] paramInput = { "test-vectors/ed25519-rfc-8032.yaml", "test-vectors/ed25519-python.yaml" };
        ArrayList<Object[]> params = new ArrayList<>();
        for (String paramFile : paramInput) {
            TextWire textWire = new TextWire(BytesUtil.readFile(paramFile)).useTextDocuments();
            List<Map<String, Object>> testData = (List<Map<String, Object>>) textWire.readMap().get("tests");
            for (Map<String, Object> data : testData) {
                String[] param = new String[5];
                param[0] = data.get("SECRET KEY").toString();
                param[1] = data.get("PUBLIC KEY").toString();
                param[2] = data.get("MESSAGE").toString();
                param[3] = data.get("SIGNATURE").toString();
                param[4] = data.get("NAME").toString();
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
        assumeFalse(OS.isWindows());

        Bytes<?> privateKeyBuffer = null;
        Bytes<?> secretKeyBuffer = null;
        Bytes<?> privateOrSecret = bft.fromHex(privateOrSecretKey);
        if (privateOrSecret.readRemaining() == Ed25519.SECRET_KEY_LENGTH) {
            secretKeyBuffer = privateOrSecret;
        } else {
            privateKeyBuffer = privateOrSecret;
        }

        Bytes<?> publicKeyBuffer = bft.fromHex(publicKey);
        if (secretKeyBuffer == null) {
            secretKeyBuffer = bft.bytesWithZeros(Ed25519.SECRET_KEY_LENGTH);
            Bytes<?> tmpPublicKeyBuffer = bft.bytesWithZeros(Ed25519.PUBLIC_KEY_LENGTH);
            Ed25519.privateToPublicAndSecret(tmpPublicKeyBuffer, secretKeyBuffer, privateKeyBuffer);
            assertEquals(publicKeyBuffer.toHexString(), tmpPublicKeyBuffer.toHexString());
        }
        Bytes<?> messageBuffer = bft.fromHex(message);
        Bytes<?> signExpectedBuffer;
        if (signExpected.length() == 128) {
            signExpectedBuffer = Bytes.wrapForRead(DatatypeConverter.parseHexBinary(signExpected + message));
        } else {
            signExpectedBuffer = Bytes.wrapForRead(DatatypeConverter.parseHexBinary(signExpected));
        }
        Bytes<?> signedMsgBuffer = bft.fromHex(Ed25519.SIGNATURE_LENGTH, message);
        signedMsgBuffer.writePosition(0);
        Ed25519.sign(signedMsgBuffer, messageBuffer, secretKeyBuffer);
        assertEquals(signExpectedBuffer.toHexString(), signedMsgBuffer.toHexString());
        signedMsgBuffer.readPosition(0);
        publicKeyBuffer.readPositionRemaining(0, Ed25519.PUBLIC_KEY_LENGTH);
        assertTrue(Ed25519.verify(signedMsgBuffer, publicKeyBuffer));
    }

    @Test
    public void signAndVerifyDetached() {
        assumeFalse(OS.isWindows());

        Bytes<?> privateKeyBuffer = null;
        Bytes<?> secretKeyBuffer = null;
        Bytes<?> privateOrSecret = bft.fromHex(privateOrSecretKey);
        if (privateOrSecret.readRemaining() == Ed25519.SECRET_KEY_LENGTH) {
            secretKeyBuffer = privateOrSecret;
        } else {
            privateKeyBuffer = privateOrSecret;
        }

        Bytes<?> publicKeyBuffer = bft.fromHex(publicKey);
        if (secretKeyBuffer == null) {
            secretKeyBuffer = bft.bytesWithZeros(Ed25519.SECRET_KEY_LENGTH);
            Bytes<?> tmpPublicKeyBuffer = bft.bytesWithZeros(Ed25519.PUBLIC_KEY_LENGTH);
            Ed25519.privateToPublicAndSecret(tmpPublicKeyBuffer, secretKeyBuffer, privateKeyBuffer);
            assertEquals(publicKeyBuffer.toHexString(), tmpPublicKeyBuffer.toHexString());
        }
        Bytes<?> messageBuffer = bft.fromHex(message);
        Bytes<?> signExpectedBuffer = Bytes.wrapForRead(DatatypeConverter.parseHexBinary(signExpected.substring(0, 128)));

        final int length = messageBuffer.length();
        Ed25519.sign(messageBuffer, length, 0, length, secretKeyBuffer);
        assertEquals(signExpectedBuffer.toHexString(), messageBuffer.subBytes(length, 64).bytesForRead().toHexString());
        publicKeyBuffer.readPositionRemaining(0, Ed25519.PUBLIC_KEY_LENGTH);
        assertTrue(Ed25519.verify(messageBuffer, length, 0, length, publicKeyBuffer));
    }
}