package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesUtil;
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

@RunWith(Parameterized.class)
public class BatchSha256Rc4Test {
    static BytesForTesting bft = new BytesForTesting();
    static int testCounter = 0;
    static long timePassed = 0;
    private static final ThreadLocal<Bytes<?>> hash256Bytes = ThreadLocal.withInitial(() -> Bytes.allocateDirect(SHA2.HASH_SHA256_BYTES));
    private static Bytes<?> testDataBytes;
    @Parameter(0) public String name;
    @Parameter(1) public long size;
    @Parameter(2) public String sha256;

    @SuppressWarnings("unchecked")
    @Parameters(name = "{0}")
    public static Collection<Object[]> data() throws IOException {
        String paramFile = "test-vectors/sha256-shadd256.yaml";
        ArrayList<Object[]> params = new ArrayList<>();
        int maxTestsToRun = 3500;
        TextWire textWire = new TextWire(BytesUtil.readFile(paramFile)).useTextDocuments();
        List<Map<String, Object>> testData = (List<Map<String, Object>>) textWire.readMap().get("tests");
        long maxSize = 0;
        for (Map<String, Object> data : testData) {
            Object[] param = new Object[3];
            param[0] = data.get("NAME");
            long size = Long.parseLong(data.get("SIZE").toString());
            param[1] = size;
            param[2] = data.get("HASH");
            params.add(param);
            maxSize = Math.max(maxSize, size);
            if (--maxTestsToRun == 0) {
                break;
            }
        }
        testDataBytes = generateRc4(maxSize);
        return params;
    }

    @AfterClass
    public static void after() {
        bft.cleanup();
    }

    public static Bytes<?> generateRc4(long len) {
        int[] key = new int[] { 0 };
        Rc4Cipher cipher = new Rc4Cipher(key);
        Bytes<?> bytes = Bytes.allocateDirect(len);
        cipher.prga(bytes, len);
        return bytes;
    }

    @Test
    public void testHash() {
        if ((testCounter % 250) == 0) {
            long newTime = System.currentTimeMillis();
            System.out.println("Executing test number " + testCounter + " for data size " + size + " time since last log "
                    + String.format("%.2f", ((newTime - timePassed) / 1000.0)) + " sec(s)");
            timePassed = newTime;
        }
        testCounter++;
        Bytes<?> bytesMessage = testDataBytes;
        bytesMessage.readPositionRemaining(0, size);
        Bytes<?> sha256Actual = hash256Bytes.get();
        sha256Actual.writePosition(0);
        SHA2.appendSha256(sha256Actual, bytesMessage);
        sha256Actual.readPosition(0);

        Bytes<?> sha256Expected = bft.fromHex(sha256);
        sha256Expected.readPosition(0);

        assertEquals(sha256Expected.toHexString(SHA2.HASH_SHA256_BYTES), sha256Actual.toHexString(SHA2.HASH_SHA256_BYTES));
        sha256Expected.releaseLast();
    }
}
