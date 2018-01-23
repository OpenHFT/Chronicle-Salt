package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;

import javax.xml.bind.DatatypeConverter;
import java.util.stream.IntStream;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

public class SignAndVerifyPerfMain {
    public static void main(String[] args) {
        final String SIGN_PRIVATE = "b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd";

        Bytes publicKey = Bytes.allocateDirect(32);
        Bytes secretKey = Bytes.allocateDirect(64);
        BytesStore privateKey = fromHex(SIGN_PRIVATE);
        Ed25519.privateToPublicAndSecret(publicKey, secretKey, privateKey);
        assertEquals(32, publicKey.readRemaining());
        assertEquals(64, secretKey.readRemaining());

        ThreadLocal<Bytes> sigAndMsg = ThreadLocal.withInitial(() -> Bytes.allocateDirect(64 + 64));

        for (int t = 0; t < 50; t++) {
            int runs = 128;
            long start = System.nanoTime();
            Bytes bytes = sigAndMsg.get();
            Ed25519.sign(bytes, privateKey, secretKey);
            IntStream.range(0, runs).parallel().forEach(i -> {
                assertTrue(Ed25519.verify(bytes, publicKey));
            });
            long time = System.nanoTime() - start;
            System.out.println("Throughput: " + (long) (runs * 1e9 / time));
        }
    }

    static Bytes fromHex(String s) {
        byte[] byteArr = DatatypeConverter.parseHexBinary(s);
        Bytes bytes = Bytes.allocateDirect(byteArr.length);
        bytes.write(byteArr);
        return bytes;
    }
}
