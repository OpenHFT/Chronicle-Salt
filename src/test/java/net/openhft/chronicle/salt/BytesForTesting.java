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

import javax.xml.bind.DatatypeConverter;
import java.util.ArrayList;
import java.util.List;

import static junit.framework.TestCase.fail;
import static org.junit.Assert.assertEquals;

@SuppressWarnings("rawtypes")
public class BytesForTesting {

    final List<Bytes<?>> bytesList = new ArrayList<>();

    static void checkPseudoRandom(Bytes<?> bytes) throws java.nio.BufferUnderflowException {
        checkPseudoRandom(bytes, bytes.realCapacity());
    }

    static void checkPseudoRandom(Bytes<?> bytes, long size) throws java.nio.BufferUnderflowException {
        bytes.readPositionRemaining(0, size);
        int count = 0;
        while (bytes.readRemaining() > 7) {
            count += Long.bitCount(bytes.readLong());
        }
        assertEquals(size * 4, count, size);
    }

    Bytes<?> fromHex(String s) {
        return fromHex(0, s);
    }

    Bytes<?> fromHex(int padding, String s) {
        byte[] byteArr = DatatypeConverter.parseHexBinary(s);
        Bytes<?> bytes = bytesWithZeros(padding + byteArr.length);
        if (padding > 0) {
            bytes.zeroOut(0, padding);
            bytes.writePosition(padding);
        }
        bytes.write(byteArr);
        return bytes;
    }

    Bytes<?> bytesWithZeros(long size) {
        Bytes<?> b = Bytes.allocateDirect(size + 64);
        b.zeroOut(0, b.realCapacity());
        bytesList.add(b);
        return b;
    }

    void cleanup() {
        bytesList.forEach(b -> {
            if (b.refCount() > 0) {
                b.releaseLast();
            }
        });
        bytesList.clear();
    }

    void checkZeros(Bytes<?> b) {
        for (int i = 8; i <= 32; i += 8) {
            if (b.readLong(b.realCapacity() - i) != 0) {
                fail(b.toHexString());
            }
        }
    }

    void compare(Bytes<?> signExpected, Bytes<?> signedMsg, int len) {
        for (int i = 0; i < len; i++) {
            assertEquals("Byte number " + i, signExpected.readByte(), signedMsg.readByte());
        }
    }
}
