package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.bytes.internal.NativeBytesStore;
import net.openhft.chronicle.core.OS;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;

import static net.openhft.chronicle.salt.TestUtil.nativeBytesStore;
import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeFalse;

public class Blake2bTest {

    // https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2-kat.json for test vectors

    private static void doTestBlake2b256(String inputStr, String expectedHex) {
        doTestBlake2b256(inputStr.getBytes(), expectedHex);
    }

    private static void doTestBlake2b256(byte[] inputStr, String expectedHex) {
        Bytes<?> input = Bytes.allocateElasticDirect();
        input.write(inputStr);
        Bytes<?> hashBlake = Bytes.allocateElasticDirect();
        Blake2b.append256(hashBlake, input);
        Bytes<?> expected = Bytes.allocateElasticDirect();
        expected.write(DatatypeConverter.parseHexBinary(expectedHex));
        assertEquals(expected.toHexString(), hashBlake.toHexString());
        expected.releaseLast();
        input.releaseLast();
        hashBlake.releaseLast();
    }

    private static void doTestBlake2b512(byte[] inputStr, String expectedHex) {
        Bytes<?> input = Bytes.allocateElasticDirect();
        input.write(inputStr);
        Bytes<?> hashBlake = Bytes.allocateElasticDirect();
        Blake2b.append512(hashBlake, input);
        Bytes<?> expected = Bytes.allocateElasticDirect();
        expected.write(DatatypeConverter.parseHexBinary(expectedHex));
        assertEquals(expected.toHexString(), hashBlake.toHexString());
        expected.releaseLast();
        input.releaseLast();
        hashBlake.releaseLast();
    }

    @Test
    public void testHash256() {
        doTestBlake2b256(new byte[0], "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
        doTestBlake2b256("abc".getBytes(), "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
        doTestBlake2b256(DatatypeConverter.parseHexBinary("de188941a3375d3a8a061e67576e926d"),
                "ad998c6554e8233c3b87edf20053a233f13840a6c84069d00d2553f3c426323e");
        doTestBlake2b256(
                DatatypeConverter.parseHexBinary(
                        "de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc75076d9fb9c5417aa5cb30fc22198b34982dbb629e"),
                "4073644f3ddd85c44ccd932606c5280ea0557d08e716537031e689f860f8b012");

        doTestBlake2b256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "5f7a93da9c5621583f22e49e8e91a40cbba37536622235a380f434b9f68e49c4");
        doTestBlake2b256("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "90a0bcf5e5a67ac1578c2754617994cfc248109275a809a0721feebd1e918738");
        StringBuilder strOneMillionChara = new StringBuilder();
        for (int i = 0; i < 1_000_000; i++) {
            strOneMillionChara.append('a');
        }
        doTestBlake2b256(strOneMillionChara.toString(), "0741850f36cba4259628355d1073e24ddb9ca0e1bfac36fd39ae5dc2101e23a4");
    }

    @Test
    public void testMultiPart256() {
        assumeFalse(OS.isWindows());

        Blake2b.MultiPart256 multi = new Blake2b.MultiPart256();
        assertMultiPart256(multi, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
                NativeBytesStore.from(new byte[0]));

        assertMultiPart256(multi, "03170A2E7597B7B7E3D84C05391D139A62B157E78786D8C082F29DCF4C111314",
                NativeBytesStore.from(new byte[]{0}));

        assertMultiPart256(multi, "117AD6B940F5E8292C007D9C7E7350CD33CF85B5887E8DA71C7957830F536E7C",
                nativeBytesStore("abcdefgh"),
                nativeBytesStore("ijklmnop"),
                nativeBytesStore("qrstuvwxyz"));

        // hypercore leaf batch example
        assertMultiPart256(multi, "CCFA4259EE7C41E411E5770973A49C5CEFFB5272D6A37F2C6F2DAC2190F7E2B7",
                NativeBytesStore.from(new byte[]{0}),                        // leafy type
                NativeBytesStore.from(new byte[]{0, 0, 0, 0, 0, 0, 0, 11}),  // message length
                nativeBytesStore("hello world"));                       // message

        assertMultiPart256(multi, "BAB07BD8DB18F6431170DF84DCFED749D7FA9EAC9E2C6BFE346F26453A65EAFC",
                NativeBytesStore.from(new byte[]{0}),                        // leafy type
                NativeBytesStore.from(new byte[]{0, 0, 0, 0, 0, 0, 0, 11}),  // message length
                nativeBytesStore("world hello"));                       // message
    }

    @Test
    public void testHash512() {
        assumeFalse(OS.isWindows());

        doTestBlake2b512(new byte[0], "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
        doTestBlake2b512("abc".getBytes(), "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
        doTestBlake2b512(DatatypeConverter.parseHexBinary("000102030405060708090a0b0c0d0e0f10"),
                "9c4d0c3e1cdbbf485bec86f41cec7c98373f0e09f392849aaa229ebfbf397b22085529cb7ef39f9c7c2222a514182b1effaa178cc3687b1b2b6cbcb6fdeb96f8");
        doTestBlake2b512(DatatypeConverter.parseHexBinary(
                        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b" +
                                "2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b"),
                "3c9a7359ab4febce07b20ac447b06a240b7fe1dae5439c49b60b5819f7812e4c172406c1aac316713cf0dded1038077258e2eff5b33913d9d95caeb4e6c6b970");

        doTestBlake2b512(DatatypeConverter.parseHexBinary(
                        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
                                "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
                                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f" +
                                "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
                                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
                                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfe"),
                "5b21c5fd8868367612474fa2e70e9cfa2201ffeee8fafab5797ad58fefa17c9b5b107da4a3db6320baaf2c8617d5a51df914ae88da3867c2d41f0cc14fa67928");
        StringBuilder strOneMillionChara = new StringBuilder();
        for (int i = 0; i < 1_000_000; i++) {
            strOneMillionChara.append('a');
        }
        doTestBlake2b512(strOneMillionChara.toString().getBytes(), "98fb3efb7206fd19ebf69b6f312cf7b64e3b94dbe1a17107913975a793f177e1d077609d7fba363cbba00d05f7aa4e4fa8715d6428104c0a75643b0ff3fd3eaf");
    }

    @Test
    public void testMultiPart512() {
        assumeFalse(OS.isWindows());

        Blake2b.MultiPart512 multi = new Blake2b.MultiPart512();

        assertMultiPart512(multi, "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
                NativeBytesStore.from(new byte[0]));

        assertMultiPart512(multi, "2FA3F686DF876995167E7C2E5D74C4C7B6E48F8068FE0E44208344D480F7904C36963E44115FE3EB2A3AC8694C28BCB4F5A0F3276F2E79487D8219057A506E4B",
                NativeBytesStore.from(new byte[]{0}));

        assertMultiPart512(multi,
                "C68EDE143E416EB7B4AAAE0D8E48E55DD529EAFED10B1DF1A61416953A2B0A5666C761E7D412E6709E31FFE221B7A7A73908CB95A4D120B8B090A87D1FBEDB4C",
                nativeBytesStore("abcdefgh"),
                nativeBytesStore("ijklmnop"),
                nativeBytesStore("qrstuvwxyz"));

        // hypercore leaf batch example
        assertMultiPart512(multi, "E623E28724C7815EB82FAE2F32A186EB6B70C3DA63B721D7B16094EB0DE6FF29969079BAC8F7DEA85CFCB24226775BAAEC2FE27F09B55BA477FEED41DEE36712",
                NativeBytesStore.from(new byte[]{0}),                        // leafy type
                NativeBytesStore.from(new byte[]{0, 0, 0, 0, 0, 0, 0, 11}),  // message length
                nativeBytesStore("hello world"));                           // message

        assertMultiPart512(multi, "0B0595CB66B3E920FFF80F33441FF7A2CE3E269B7B4DCBF24065B87AEA43B31D5763EFD62E512F416D931C6904C852D403F23738DD33F72062EA209FA0265A49",
                NativeBytesStore.from(new byte[]{0}),                        // leafy type
                NativeBytesStore.from(new byte[]{0, 0, 0, 0, 0, 0, 0, 11}),  // message length
                nativeBytesStore("world hello"));                           // message
    }

    private void assertMultiPart256(Blake2b.MultiPart256 multi, String expectedHex, BytesStore... messages) {
        for (BytesStore message : messages) {
            multi.add(message);
        }
        assertEquals(expectedHex.toUpperCase(), DatatypeConverter.printHexBinary(multi.hash().toByteArray()));
        multi.reset();
    }

    private void assertMultiPart512(Blake2b.MultiPart512 multi, String expectedHex, BytesStore... messages) {
        for (BytesStore message : messages) {
            multi.add(message);
        }
        assertEquals(expectedHex.toUpperCase(), DatatypeConverter.printHexBinary(multi.hash().toByteArray()));
        multi.reset();
    }
}
