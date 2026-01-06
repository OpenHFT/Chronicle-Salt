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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

@SuppressWarnings("rawtypes")
public class BatchSignAndVerifyEd25519Test {
    private static final BytesForTesting bft = new BytesForTesting();
    private static List<Arguments> cachedParameters;

    @SuppressWarnings("unchecked")
    static Stream<Arguments> data() throws IOException {
        if (cachedParameters != null) {
            return cachedParameters.stream();
        }
        String[] paramInput = { "test-vectors/ed25519-rfc-8032.yaml", "test-vectors/ed25519-python.yaml" };
        List<Arguments> params = new ArrayList<>();
        for (String paramFile : paramInput) {
            TextWire textWire = new TextWire(BytesUtil.readFile(paramFile)).useTextDocuments();
            List<Map<String, Object>> testData = (List<Map<String, Object>>) textWire.readMap().get("tests");
            for (Map<String, Object> data : testData) {
                params.add(Arguments.of(data.get("SECRET KEY").toString(), data.get("PUBLIC KEY").toString(), data.get("MESSAGE").toString(),
                        data.get("SIGNATURE").toString(), data.get("NAME").toString()));
            }
        }
        cachedParameters = params;
        return params.stream();
    }

    @AfterAll
    static void teardownClass() {
        bft.cleanup();
    }

    @ParameterizedTest(name = "{4}")
    @MethodSource("data")
    public void signAndVerify(String privateOrSecretKey, String publicKey, String message, String signExpected, String testName) {
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
            assertEquals(publicKeyBuffer.toHexString(), tmpPublicKeyBuffer.toHexString(), "public key derives from private key");
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
        assertEquals(signExpectedBuffer.toHexString(), signedMsgBuffer.toHexString(), "signature matches");
        signedMsgBuffer.readPosition(0);
        publicKeyBuffer.readPositionRemaining(0, Ed25519.PUBLIC_KEY_LENGTH);
        assertTrue(Ed25519.verify(signedMsgBuffer, publicKeyBuffer), "signature verifies");
    }

    @ParameterizedTest(name = "{4} (detached)")
    @MethodSource("data")
    public void signAndVerifyDetached(String privateOrSecretKey, String publicKey, String message, String signExpected, String testName) {
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
            assertEquals(publicKeyBuffer.toHexString(), tmpPublicKeyBuffer.toHexString(), "public key derives from private key");
        }
        Bytes<?> messageBuffer = bft.fromHex(message);
        Bytes<?> signExpectedBuffer = Bytes.wrapForRead(DatatypeConverter.parseHexBinary(signExpected.substring(0, 128)));

        final int length = messageBuffer.length();
        Ed25519.sign(messageBuffer, length, 0, length, secretKeyBuffer);
        assertEquals(signExpectedBuffer.toHexString(), messageBuffer.subBytes(length, 64).bytesForRead().toHexString(), "detached signature matches");
        publicKeyBuffer.readPositionRemaining(0, Ed25519.PUBLIC_KEY_LENGTH);
        assertTrue(Ed25519.verify(messageBuffer, length, 0, length, publicKeyBuffer), "detached signature verifies");
    }
}
