package net.openhft.chronicle.salt;

import static junit.framework.TestCase.fail;
import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import net.openhft.chronicle.bytes.Bytes;

@SuppressWarnings("rawtypes")
public class BytesForTest {

	static final List<Bytes<?>> bytesList = new ArrayList<>();

	static Bytes fromHex(String s) {
		return fromHex(0, s);
	}

	static Bytes fromHex(int padding, String s) {
		byte[] byteArr = DatatypeConverter.parseHexBinary(s);
		Bytes bytes = bytesWithZeros(padding + byteArr.length);
		if (padding > 0) {
			bytes.zeroOut(0, padding);
			bytes.writePosition(padding);
		}
		bytes.write(byteArr);
		return bytes;
	}

	static Bytes bytesWithZeros(int size) {
		Bytes b = Bytes.allocateDirect(size + 32);
		b.zeroOut(0, b.realCapacity());
		bytesList.add(b);
		return b;
	}

	static void cleanup() {
		bytesList.forEach(b -> b.release());
		bytesList.clear();
	}

	static void checkZeros(Bytes b) {
		for (int i = 8; i <= 32; i += 8) {
			if (b.readLong(b.realCapacity() - i) != 0) {
				fail(b.toHexString());
			}
		}
	}

	static void checkPseudoRandom(Bytes bytes, long size) throws java.nio.BufferUnderflowException {
		bytes.readPositionRemaining(0, size);
		int count = 0;
		while (bytes.readRemaining() > 7) {
			count += Long.bitCount(bytes.readLong());
		}
		assertEquals(size * 4, count, size);
	}

	static void compare(Bytes signExpected, Bytes signedMsg, int len) {
		for (int i = 0; i < len; i++) {
			assertEquals("Byte number " + i, signExpected.readByte(), signedMsg.readByte());
		}
	}
}
