package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.core.Jvm;

import javax.xml.bind.DatatypeConverter;
import java.util.stream.IntStream;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

/*
Windows 10 laptop, i7-7700HQ CPU @ 2.80GHz, 2801 Mhz, 4 Core(s), 8 Logical Processor(s)
Throughput: Sign: 64013/s, Verify: 30022/s
Throughput: Sign: 68490/s, Verify: 26917/s

Centos 7, Intel(R) Core(TM) i7-7820X CPU @ 3.60GHz
Throughput: Sign: 259851/s, Verify: 103771/s
Throughput: Sign: 263146/s, Verify: 108373/s

Centos 7, Dual Intel(R) Xeon(R) CPU E5-2650 v4 @ 2.90GHz
Throughput: Sign: 503524/s, Verify: 207797/s
Throughput: Sign: 510287/s, Verify: 198604/s

Unbuntu, Ryzen 9 59050X
Throughput: Sign: 568424/s, Verify: 302609/s
 */
public class SignAndVerifyPerfMain {
    public static void main(String[] args) {
        final String SIGN_PRIVATE = "b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd";

        Bytes<?> publicKey = Bytes.allocateDirect(32);
        Bytes<?> secretKey = Bytes.allocateDirect(64);
        BytesStore<?, ?> privateKey = fromHex(SIGN_PRIVATE);
        Ed25519.privateToPublicAndSecret(publicKey, secretKey, privateKey);
        assertEquals(32, publicKey.readRemaining());
        assertEquals(64, secretKey.readRemaining());

        ThreadLocal<Bytes<?>> sigAndMsg = ThreadLocal.withInitial(() -> Bytes.allocateDirect(64 + 64));
        ThreadLocal<Bytes<?>> sigAndMsg2 = ThreadLocal.withInitial(() -> Bytes.allocateDirect(64 + 64));

        int procs = Runtime.getRuntime().availableProcessors();
        for (int t = 0; t < 10; t++) {
            int runs = procs * 20;
            long start = System.nanoTime();
            IntStream.range(0, runs).parallel().forEach(i -> {
                sigAndMsg.get().writePosition(0);
                Ed25519.sign(sigAndMsg.get(), secretKey, secretKey);
                sigAndMsg2.get().writePosition(0);
                Ed25519.sign(sigAndMsg2.get(), privateKey, secretKey);
            });
            long time = System.nanoTime() - start;

            Bytes<?> bytes = sigAndMsg.get();
            bytes.writePosition(0);
            Bytes<?> bytes2 = sigAndMsg2.get();
            bytes2.writePosition(0);
            Ed25519.sign(bytes, secretKey, secretKey);
            Ed25519.sign(bytes2, privateKey, secretKey);
            long start2 = System.nanoTime();
            IntStream.range(0, runs).parallel().forEach(i -> {
                assertTrue(Ed25519.verify(bytes, publicKey));
                assertTrue(Ed25519.verify(bytes2, publicKey));
            });
            long time2 = System.nanoTime() - start2;
            System.out.println(
                    "Throughput: " + "Sign: " + (long) ((2 * runs * 1e9) / time) + "/s, " + "Verify: " + (long) ((2 * runs * 1e9) / time2) + "/s");
            Jvm.pause(100);
        }
    }

    static Bytes<?> fromHex(String s) {
        byte[] byteArr = DatatypeConverter.parseHexBinary(s);
        Bytes<?> bytes = Bytes.allocateDirect(byteArr.length);
        bytes.write(byteArr);
        return bytes;
    }
}
