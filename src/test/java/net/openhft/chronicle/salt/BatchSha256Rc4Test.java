package net.openhft.chronicle.salt;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesUtil;
import net.openhft.chronicle.wire.TextWire;

@RunWith(Parameterized.class)
public class BatchSha256Rc4Test {
    @Parameter(0) public String name;
    @Parameter(1) public int size;
    @Parameter(2) public String sha256;

    @SuppressWarnings("unchecked")
    @Parameters(name = "{0}")
    public static Collection<Object[]> data() throws IOException {
        String[] paramInput = { "test-vectors/shadd256.yaml" };
        ArrayList<Object[]> params = new ArrayList<>();
        for (String paramFile : paramInput) {
            TextWire textWire = new TextWire(BytesUtil.readFile(paramFile));
            List<Map<String, Object>> testData = (List<Map<String, Object>>) textWire.readMap().get("tests");
            int i = 0;
            for (Map<String, Object> data : testData) {
                i++;
                Object[] param = new Object[3];
                param[0] = data.get("NAME");
                if ((Long) data.get("SIZE") <= Integer.MAX_VALUE) {
                    // System.out.println(data.get("SIZE") + " " + Integer.MAX_VALUE);
                    param[1] = Integer.parseInt(data.get("SIZE").toString());
                    param[2] = data.get("HASH");
                    params.add(param);
                } else {
                    System.out.println("skipping " + data.get("SIZE"));
                }
                if (i > 30) {
                    break;
                }
            }
        }
        return params;
    }

    static ThreadLocal<Bytes<?>> hash256Bytes = ThreadLocal.withInitial(() -> Bytes.allocateDirect(SHA2.HASH_SHA256_BYTES));

    @Test
    public void testHash() {
        String message = generateRca(size);
        Bytes<?> hash256 = hash256Bytes.get();
        hash256.writePosition(0);
        System.out.println(message);
        Bytes<?> bytesMessage = Bytes.fromHexString(message);
        bytesMessage.readPosition(0);
        SHA2.sha256(hash256, bytesMessage);
        System.out.println(hash256.toString());
        hash256.readPosition(0);
        assertEquals(sha256, hash256.toHexString());
    }

    public static String generateRca(int len) {
        int[] key = new int[] { 0 };
        Rc4Cipher cipher = new Rc4Cipher(key);
        int[] bytes = new int[len];
        // cipher.prga(bytes);
        StringBuilder strB = new StringBuilder();
        for (int i : bytes) {
            strB.append(Integer.toHexString(i));
        }
        return strB.toString();
    }
}
