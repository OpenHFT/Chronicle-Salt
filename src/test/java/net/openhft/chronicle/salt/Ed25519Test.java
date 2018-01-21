package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import org.junit.After;
import org.junit.Ignore;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.util.ArrayList;
import java.util.List;

import static junit.framework.TestCase.fail;
import static org.junit.Assert.assertEquals;

public class Ed25519Test {
    static final List<Bytes<?>> BYTES_LIST = new ArrayList<>();

    static Bytes bytesWithZeros(int size) {
        Bytes b = Bytes.allocateDirect(size + 32);
        b.zeroOut(0, b.realCapacity());
        BYTES_LIST.add(b);
        return b;
    }

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

    static void checkZeros(Bytes b) {
        for (int i = 8; i <= 32; i += 8)
            if (b.readLong(b.realCapacity() - i) != 0)
                fail(b.toHexString());
    }

    static void checkPseudoRandom(Bytes bytes, long size) throws java.nio.BufferUnderflowException {
        bytes.readPositionRemaining(0, size);
        int count = 0;
        while (bytes.readRemaining() > 7)
            count += Long.bitCount(bytes.readLong());

        assertEquals(size * 4, count, size);
    }

    @After
    public void tearDown() {
        BYTES_LIST.forEach(b -> b.release());
        BYTES_LIST.clear();
    }

    @Test
    public void secretKey() {
        final String SIGN_PRIVATE = "B18E1D0045995EC3D010C387CCFEB984D783AF8FBB0F40FA7DB126D889F6DADD";
        Bytes privateKey = fromHex(SIGN_PRIVATE);

        Bytes publicKey = bytesWithZeros(32);
        Ed25519.privateToPublic(publicKey, privateKey);

        final String SIGN_PUBLIC = "7AB107CE67B8E8898830C7EE9229AC4AA8B1B33DB2D198DD20D0879E8E521D14";
        Bytes publicKey0 = fromHex(SIGN_PUBLIC);
        assertEquals(publicKey0.toHexString(), publicKey.toHexString());
    }

    @Test
    public void generateKey() {
        Bytes publicKey = bytesWithZeros(32);
        Bytes privateKey = bytesWithZeros(32);
        Ed25519.generateKey(privateKey, publicKey);
        checkZeros(publicKey);
        checkZeros(privateKey);
        checkPseudoRandom(privateKey, 32);
        checkPseudoRandom(publicKey, 32);
    }

    @Test
    @Ignore
    public void sign() {
        final String SIGN_PRIVATE = "B18E1D0045995EC3D010C387CCFEB984D783AF8FBB0F40FA7DB126D889F6DADD";
        Bytes privateKey = fromHex(SIGN_PRIVATE);
        Bytes publicKey = bytesWithZeros(32);
        Bytes secretKey = bytesWithZeros(64);
        Ed25519.privateToPublicAndSecret(publicKey, secretKey, privateKey);
        checkZeros(secretKey);
        checkZeros(privateKey);
        Bytes signAndMsg = bytesWithZeros(64 + 32);
        Ed25519.sign(signAndMsg, privateKey, privateKey);
        checkZeros(signAndMsg);
        // doesn't look right.
        String SIGN_EXPECTED = "86b4707fadb1ef4613efadd12143cd9dffb2eac329c38923c03f9e315c3dd33bde1ef101137fbc403eb3f3d7ff283155053c667eb65908fe6fcd653eab550e0f";
        Bytes signExpected = fromHex(SIGN_EXPECTED);
        assertEquals(signExpected.toHexString(), signAndMsg.toHexString());
    }

    @Test
    @Ignore
    public void verify() {
    }
}