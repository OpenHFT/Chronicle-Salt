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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeFalse;

@RunWith(Parameterized.class)
public class BatchSha256Sha512RandomTest {
    private static final ThreadLocal<Bytes<?>> hash256Bytes = ThreadLocal.withInitial(() -> Bytes.allocateDirect(SHA2.HASH_SHA256_BYTES));
    private static final ThreadLocal<Bytes<?>> hash512Bytes = ThreadLocal.withInitial(() -> Bytes.allocateDirect(SHA2.HASH_SHA512_BYTES));
    static BytesForTesting bft = new BytesForTesting();
    @Parameter(0) public String data;
    @Parameter(1) public int size;
    @Parameter(2) public String sha256;
    @Parameter(3) public String sha512;

    @SuppressWarnings("unchecked")
    @Parameters(name = "{1}")
    public static Collection<Object[]> data() throws IOException {
        String[] paramInput = { "test-vectors/random-sha256_sha512.yaml" };
        ArrayList<Object[]> params = new ArrayList<>();
        for (String paramFile : paramInput) {
            Bytes<?> bytes = BytesUtil.readFile(paramFile);
            TextWire textWire = new TextWire(bytes).useTextDocuments();
            Map<Object, Object> map = textWire.readMap();
            List<Map<String, Object>> testData = (List<Map<String, Object>>) map.get("tests");
            for (Map<String, Object> data : testData) {
                Object[] param = new Object[4];
                param[0] = data.get("DATA");
                param[1] = Integer.parseInt(data.get("SIZE").toString());
                param[2] = data.get("SHA256");
                param[3] = data.get("SHA512");
                params.add(param);
            }
        }
        return params;
    }

    @AfterClass
    public static void after() {
        bft.cleanup();
    }

    @Test
    public void testHash() {
        assumeFalse(OS.isWindows());

        Bytes<?> bytesMessage = bft.fromHex(data);
        bytesMessage.readPosition(0);
        bytesMessage.readPositionRemaining(0, size);

        Bytes<?> actualSha256 = hash256Bytes.get();
        actualSha256.writePosition(0);
        SHA2.appendSha256(actualSha256, bytesMessage);
        actualSha256.readPosition(0);
        Bytes<?> expectedSha256 = bft.fromHex(sha256);
        actualSha256.readPosition(0);
        assertEquals(expectedSha256.toHexString(), actualSha256.toHexString());
        expectedSha256.releaseLast();

        bytesMessage.readPositionRemaining(0, size);
        Bytes<?> actualSha512 = hash512Bytes.get();
        actualSha512.writePosition(0);
        SHA2.appendSha512(actualSha512, bytesMessage);
        actualSha512.readPosition(0);
        Bytes<?> expectedSha512 = bft.fromHex(sha512);
        actualSha512.readPosition(0);
        assertEquals(expectedSha512.toHexString(), actualSha512.toHexString());
        expectedSha512.releaseLast();

        bytesMessage.releaseLast();
    }
}
