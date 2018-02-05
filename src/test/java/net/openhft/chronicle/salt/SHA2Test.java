package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;

import static org.junit.Assert.assertEquals;

public class SHA2Test {
    private static void doTest256(byte[] inputStr, String expectedHex) {
        Bytes input = Bytes.allocateElasticDirect();
        input.write(inputStr);
        Bytes hash256 = Bytes.allocateElasticDirect();
        SHA2.sha256(hash256, input);
        Bytes expected = Bytes.allocateElasticDirect();
        expected.write(DatatypeConverter.parseHexBinary(expectedHex));
        assertEquals(
                expected.toHexString(),
                hash256.toHexString());
        expected.release();
        input.release();
        hash256.release();
    }

    private static void doTest512(String inputStr, String expectedHex) {
        Bytes input = Bytes.allocateElasticDirect();
        input.append(inputStr);
        Bytes hash512 = Bytes.allocateElasticDirect();
        SHA2.sha512(hash512, input);
        Bytes expected = Bytes.allocateElasticDirect();
        expected.write(DatatypeConverter.parseHexBinary(expectedHex));
        assertEquals(
                expected.toHexString(),
                hash512.toHexString());
        expected.release();
        input.release();
        hash512.release();
    }

    @Test
    public void test256() {
        doTest256(new byte[0], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        doTest256("abc".getBytes(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        doTest256(DatatypeConverter.parseHexBinary("de188941a3375d3a8a061e67576e926d"),
                "067c531269735ca7f541fdaca8f0dc76305d3cada140f89372a410fe5eff6e4d");
        doTest256(DatatypeConverter.parseHexBinary("de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc75076d9fb9c5417aa5cb30fc22198b34982dbb629e"),
                "038051e9c324393bd1ca1978dd0952c2aa3742ca4f1bd5cd4611cea83892d382");

        // TODO add https://en.wikipedia.org/wiki/SHA-2#Test_vectors
    }

    @Test
    public void test512() {
//        doTest512("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        // TODO add https://en.wikipedia.org/wiki/SHA-2#Test_vectors
    }
}
