package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;

import javax.xml.bind.DatatypeConverter;
import java.util.stream.IntStream;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

/*
Windows 10 laptop, i7-7700HQ CPU @ 2.80GHz, 2801 Mhz, 4 Core(s), 8 Logical Processor(s)
Throughput: Sign: 6965/s, Verify: 14258/s
Throughput: Sign: 49666/s, Verify: 25019/s
Throughput: Sign: 57203/s, Verify: 26649/s
Throughput: Sign: 51472/s, Verify: 24256/s
Throughput: Sign: 55636/s, Verify: 27265/s
Throughput: Sign: 56891/s, Verify: 27187/s
Throughput: Sign: 64013/s, Verify: 30022/s
Throughput: Sign: 68362/s, Verify: 22613/s
Throughput: Sign: 68044/s, Verify: 25264/s
Throughput: Sign: 68490/s, Verify: 26917/s
 */
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

        int procs = Runtime.getRuntime().availableProcessors();
        for (int t = 0; t < 10; t++) {
            int runs = procs * 10;
            long start = System.nanoTime();
            IntStream.range(0, runs).parallel().forEach(i ->
                    Ed25519.sign(sigAndMsg.get(), secretKey, secretKey));
            long time = System.nanoTime() - start;

            Bytes bytes = sigAndMsg.get();
            Ed25519.sign(bytes, privateKey, secretKey);
            long start2 = System.nanoTime();
            IntStream.range(0, runs).parallel().forEach(i -> {
                assertTrue(Ed25519.verify(bytes, publicKey));
            });
            long time2 = System.nanoTime() - start2;
            System.out.println("Throughput: Sign: " + (long) (runs * 1e9 / time) + "/s, Verify: " + (long) (runs * 1e9 / time2) + "/s");
        }
    }

    static Bytes fromHex(String s) {
        byte[] byteArr = DatatypeConverter.parseHexBinary(s);
        Bytes bytes = Bytes.allocateDirect(byteArr.length);
        bytes.write(byteArr);
        return bytes;
    }
}
