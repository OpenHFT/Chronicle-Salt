package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.bytes.NativeBytesStore;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class SHA2Test {
    private static void doTest256(String inputStr, String expectedHex) {
        doTest256(inputStr.getBytes(), expectedHex);
    }

    private static void doTest256(byte[] inputStr, String expectedHex) {
        Bytes<?> input = Bytes.allocateElasticDirect();
        input.write(inputStr);
        Bytes<?> hash256 = Bytes.allocateElasticDirect();
        SHA2.appendSha256(hash256, input);
        Bytes<?> expected = Bytes.allocateElasticDirect();
        expected.write(DatatypeConverter.parseHexBinary(expectedHex));
        assertEquals(expected.toHexString(), hash256.toHexString());
        expected.releaseLast();
        input.releaseLast();
        hash256.releaseLast();
    }

    private static void doTest512(String inputStr, String expectedHex) {
        Bytes<?> input = Bytes.allocateElasticDirect();
        input.append(inputStr);
        Bytes<?> hash512 = Bytes.allocateElasticDirect();
        SHA2.appendSha512(hash512, input);
        hash512.readPosition(0);
        Bytes<?> expected = Bytes.allocateElasticDirect();
        expected.write(DatatypeConverter.parseHexBinary(expectedHex));
        assertEquals(expected.toHexString(), hash512.toHexString());
        expected.releaseLast();
        input.releaseLast();
        hash512.releaseLast();
    }

    @Test
    public void test256() {
        doTest256(new byte[0], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        doTest256("abc".getBytes(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        doTest256(DatatypeConverter.parseHexBinary("de188941a3375d3a8a061e67576e926d"),
                "067c531269735ca7f541fdaca8f0dc76305d3cada140f89372a410fe5eff6e4d");
        doTest256(
                DatatypeConverter.parseHexBinary(
                        "de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc75076d9fb9c5417aa5cb30fc22198b34982dbb629e"),
                "038051e9c324393bd1ca1978dd0952c2aa3742ca4f1bd5cd4611cea83892d382");

        // see https://en.wikipedia.org/wiki/SHA-2#Test_vectors
        // see https://www.di-mgt.com.au/sha_testvectors.html
        doTest256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        doTest256("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
        StringBuilder strOneMillionChara = new StringBuilder();
        for (int i = 0; i < 1_000_000; i++) {
            strOneMillionChara.append('a');
        }
        doTest256(strOneMillionChara.toString(), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    @Test
    public void test512() {
        // see https://www.di-mgt.com.au/sha_testvectors.html
        doTest512("",
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        doTest512("abc",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
        doTest512("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
        doTest512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
        StringBuilder strOneMillionChara = new StringBuilder();
        for (int i = 0; i < 1_000_000; i++) {
            strOneMillionChara.append('a');
        }
        doTest512(strOneMillionChara.toString(),
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");

    }

    @Test
    public void testMultiPart256() {
        BytesStore message1 = NativeBytesStore.from("Message part1");
        BytesStore message2 = NativeBytesStore.from("Message part2");
        BytesStore message3 = NativeBytesStore.from("Message part3");

        SHA2.MultiPartSHA256 multi = new SHA2.MultiPartSHA256();
        multi.add(message1);
        multi.add(message2);
        multi.add(message3);
        BytesStore hash = multi.hash();

        assertEquals("34A26FB451F7A08C239F48D8086DCD1628FD8BDE5F54E4600EE91BA5BEBC21AB", DatatypeConverter.printHexBinary(hash.toByteArray()));
    }

    @Test
    public void testMultiPart512() {
        BytesStore message1 = NativeBytesStore.from("Message part1");
        BytesStore message2 = NativeBytesStore.from("Message part2");
        BytesStore message3 = NativeBytesStore.from("Message part3");

        SHA2.MultiPartSHA512 multi = new SHA2.MultiPartSHA512();
        multi.add(message1);
        multi.add(message2);
        multi.add(message3);
        BytesStore hash = multi.hash();

        assertEquals("D03F370D9C234701370A0323AF9BB5D0E13AEB128C6C14C427DD25B1FFCFA7EB"
                + "B505665AD2C97D989A3F460715D3C688FE04B9FC8AAA3213051486930A3B3876", DatatypeConverter.printHexBinary(hash.toByteArray()));
    }

    @Test
    public void testMultiPartREADME() {
        BytesStore message1 = NativeBytesStore.from("abcdefgh");
        BytesStore message2 = NativeBytesStore.from("ijklmnop");
        BytesStore message3 = NativeBytesStore.from("qrstuvwxyz");

        // Initialise a MultiPartSHA256 wrapper
        SHA2.MultiPartSHA256 multi256 = new SHA2.MultiPartSHA256();
        multi256.add(message1);
        multi256.add(message2);
        multi256.add(message3);

        // Generate the single SHA-256 hash of the set of messages
        BytesStore hash256 = multi256.hash();

        // Initialise a MultiPartSHA512 wrapper
        SHA2.MultiPartSHA512 multi512 = new SHA2.MultiPartSHA512();
        multi512.add(message1);
        multi512.add(message2);
        multi512.add(message3);

        // Generate the single SHA-512 hash of the set of messages
        BytesStore hash512 = multi512.hash();

        System.out.println("SHA256: " + DatatypeConverter.printHexBinary(hash256.toByteArray()));
        System.out.println("SHA512: " + DatatypeConverter.printHexBinary(hash512.toByteArray()));

        BytesStore message = NativeBytesStore.from("abcdefghijklmnopqrstuvwxyz");

        BytesStore hash1 = SHA2.sha256(message);
        assertArrayEquals(hash1.toByteArray(), hash256.toByteArray());

        BytesStore hash2 = SHA2.sha512(message);
        assertArrayEquals(hash2.toByteArray(), hash512.toByteArray());
    }
}
