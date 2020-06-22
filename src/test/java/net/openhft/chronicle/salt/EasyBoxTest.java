package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.bytes.NativeBytesStore;
import net.openhft.chronicle.core.OS;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

public class EasyBoxTest {
    @Before
    public void checkSharedLibrary() {
        assumeTrue(OS.isLinux());
    }

    @Test
    public void testKeyPairShortSeed() {
        EasyBox.KeyPair kp = EasyBox.KeyPair.deterministic(0);

        assertEquals("5BF55C73B82EBE22BE80F3430667AF570FAE2556A6415E6B30D4065300AA947D",
                DatatypeConverter.printHexBinary(kp.publicKey.store.toByteArray()));
        kp = EasyBox.KeyPair.deterministic(1);
        assertEquals("0C7B17FB4925EF41E25D75966AEA10BE2A96458DFF8CC906B4BC5312C0040528",
                DatatypeConverter.printHexBinary(kp.publicKey.store.toByteArray()));
    }

    @Test
    public void testKeyPairLongSeed() {
        BytesStore seed = NativeBytesStore.from("01234567890123456789012345678901");
        EasyBox.KeyPair kp = EasyBox.KeyPair.deterministic(seed);

        assertEquals("11BF74568407F0D337369E0F6A0375F5420B53B649CF9C9E6A44E53769A75C71",
                DatatypeConverter.printHexBinary(kp.publicKey.store.toByteArray()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testKeyPairDeterministicTooShort() {
        BytesStore seed = NativeBytesStore.from("0123456789012345678901234567");
        EasyBox.KeyPair kp = EasyBox.KeyPair.deterministic(seed);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testKeyPairDeterministicTooLong() {
        BytesStore seed = NativeBytesStore.from("0123456789012345678901234567890123456789");
        EasyBox.KeyPair kp = EasyBox.KeyPair.deterministic(seed);
    }

    @Test
    public void testSharedKey() {
        EasyBox.KeyPair alice = EasyBox.KeyPair.deterministic(123456);
        EasyBox.KeyPair bob = EasyBox.KeyPair.deterministic(456789);

        EasyBox.SharedKey sharedA = EasyBox.SharedKey.precalc(bob.publicKey, alice.secretKey);
        EasyBox.SharedKey sharedB = EasyBox.SharedKey.precalc(alice.publicKey, bob.secretKey);
        EasyBox.SharedKey sharedC = EasyBox.SharedKey.precalc(alice, bob);

        assertEquals("6F8B5C996335CF3613F4F8DA4145E4D3EDC6205B17CBD1BA855BFF1C49E65D21",
                DatatypeConverter.printHexBinary(sharedA.store.toByteArray()));

        assertEquals(DatatypeConverter.printHexBinary(sharedA.store.toByteArray()), DatatypeConverter.printHexBinary(sharedB.store.toByteArray()));

        assertEquals(DatatypeConverter.printHexBinary(sharedA.store.toByteArray()), DatatypeConverter.printHexBinary(sharedC.store.toByteArray()));
    }

    @Test
    public void testNonceSeed() {
        EasyBox.Nonce nonce = EasyBox.Nonce.deterministic(123);

        assertEquals("88998342CE06DA6A4B993CA7F71197614CB4AB230AA28FD1", DatatypeConverter.printHexBinary(nonce.store.toByteArray()));
    }

    @Test
    public void testNonceDeterministic() {
        BytesStore seed = NativeBytesStore.from("01234567890123456789012345678901");
        EasyBox.Nonce nonce = EasyBox.Nonce.deterministic(seed);
        assertEquals("B7250959EDC91EB64BDA98E347C578ACA02934FA64B56006", DatatypeConverter.printHexBinary(nonce.store.toByteArray()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNonceDeterministicTooShort() {
        BytesStore seed = NativeBytesStore.from("0123456789012345678901234567");
        EasyBox.Nonce nonce = EasyBox.Nonce.deterministic(seed);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNonceDeterministicTooLong() {
        BytesStore seed = NativeBytesStore.from("0123456789012345678901234567890123456789");
        EasyBox.Nonce nonce = EasyBox.Nonce.deterministic(seed);
    }

    @Test
    public void testNonceSequence() {
        String[] expected = { "88998342CE06DA6A4B993CA7F71197614CB4AB230AA28FD1", "89998342CE06DA6A4B993CA7F71197614CB4AB230AA28FD1",
                "8A998342CE06DA6A4B993CA7F71197614CB4AB230AA28FD1", "8B998342CE06DA6A4B993CA7F71197614CB4AB230AA28FD1",
                "8C998342CE06DA6A4B993CA7F71197614CB4AB230AA28FD1", "8D998342CE06DA6A4B993CA7F71197614CB4AB230AA28FD1",
                "8E998342CE06DA6A4B993CA7F71197614CB4AB230AA28FD1", "8F998342CE06DA6A4B993CA7F71197614CB4AB230AA28FD1",
                "90998342CE06DA6A4B993CA7F71197614CB4AB230AA28FD1", "91998342CE06DA6A4B993CA7F71197614CB4AB230AA28FD1",
                "92998342CE06DA6A4B993CA7F71197614CB4AB230AA28FD1" };

        EasyBox.Nonce nonce = EasyBox.Nonce.deterministic(123);

        for (int i = 0; i < 10; ++i) {
            assertEquals(expected[i], DatatypeConverter.printHexBinary(nonce.store.toByteArray()));
            nonce.next();
        }
    }

    @Test
    public void testEasyBox() {
        System.out.println("sodium.version= " + Sodium.SODIUM.sodium_version_string());
        BytesStore message = NativeBytesStore.from("test");

        EasyBox.KeyPair alice = EasyBox.KeyPair.generate();
        EasyBox.KeyPair bob = EasyBox.KeyPair.generate();
        EasyBox.Nonce nonce = EasyBox.Nonce.generate();

        BytesStore cipherText = EasyBox.encrypt(null, message, nonce, bob.publicKey, alice.secretKey);
        BytesStore message2 = EasyBox.decrypt(null, cipherText, nonce, alice.publicKey, bob.secretKey);

        assertTrue(Arrays.equals(message.toByteArray(), message2.toByteArray()));
    }

    @Test
    public void testEasyBox2() {
        System.out.println("sodium.version= " + Sodium.SODIUM.sodium_version_string());
        BytesStore message = NativeBytesStore.from("test");

        EasyBox.KeyPair alice = EasyBox.KeyPair.generate();
        EasyBox.KeyPair bob = EasyBox.KeyPair.generate();
        EasyBox.Nonce nonce = EasyBox.Nonce.generate();

        BytesStore cipherText = EasyBox.encrypt(message, nonce, bob.publicKey, alice.secretKey);
        BytesStore message2 = EasyBox.decrypt(cipherText, nonce, alice.publicKey, bob.secretKey);

        assertTrue(Arrays.equals(message.toByteArray(), message2.toByteArray()));
    }

    @Test
    public void testEasyBox3() {
        System.out.println("sodium.version= " + Sodium.SODIUM.sodium_version_string());
        BytesStore message = NativeBytesStore.from("test");

        EasyBox.KeyPair alice = EasyBox.KeyPair.generate();
        EasyBox.KeyPair bob = EasyBox.KeyPair.generate();
        EasyBox.Nonce nonce = EasyBox.Nonce.generate();

        BytesStore cipherText = EasyBox.encrypt(null, message, nonce.store, bob.publicKey.store, alice.secretKey.store);
        BytesStore message2 = EasyBox.decrypt(null, cipherText, nonce.store, alice.publicKey.store, bob.secretKey.store);

        assertTrue(Arrays.equals(message.toByteArray(), message2.toByteArray()));
    }

    @Test
    public void testEasyBoxMessageDeterministic() {
        BytesStore message = NativeBytesStore
                .from("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et "
                        + "dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip "
                        + "ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu "
                        + "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt "
                        + "mollit anim id est laborum.");

        EasyBox.KeyPair alice = EasyBox.KeyPair.deterministic(123);
        EasyBox.KeyPair bob = EasyBox.KeyPair.deterministic(456);
        EasyBox.Nonce nonce = EasyBox.Nonce.deterministic(789);

        String expected = "970DC924AFCBD44DD20FA514CD328575BD70B483E3C88FE4C20F1F744CE18A8E6D543C3CA3D033B36D9341F32A34A098797762503ECEB8"
                + "C5D24E0C290CA08F5B7A188D3E0E4AB55D767A31F89546171BDE69BC64AFF116DD07A196D9B5D41FF6F7D273B92705450213A2BDCBA3A7"
                + "808C96646E8F0410BF5D2BDC05C71E3A35737D3276400372C0FC53631B445B94F2AB3E4DF55B1BE3B1373BAE36E5A44F0E4B046FF2FCBA"
                + "E8C55E89FDDE6468B0F908176745BA6D1DA788EF08546CC2A675067A6C3A907C765D97EF1C2184B9B748F6081F7168C57BBFABADB0357E"
                + "892A71DCED7867E4D3225A96598FBA9E3771509493C85085DE5ED05A597A45B3B7EF0A3C3FC8A1062AD67C48407C7B7DC0522167FE8295"
                + "DA52A0D311CE995159728FB51F1D2DFEB738442A6FD7C8CA4C9FEB2ED0584D12C5359D0EA558CFC72545CBB821754959DA35F6839866E6"
                + "C04A400E0FE9D8689426E9F1EAE1D77F93026D7B9E19A56353F59EFF980090053C09FB7CCF7438366AD0B9E9DB77042C0491B540646D02"
                + "FE8BB5C3A310B126C932290DD4885915F379A475E52B4025ED495B59BAC92C5487827065B26732A52545E5FCF044DBB3D5F827CA6B7CDF"
                + "E28062EC726BA7A0B0C73C058EDC66485C69663481";

        long msglen = message.readRemaining();

        BytesStore cipherText = EasyBox.encrypt(message, nonce, bob.publicKey, alice.secretKey);
        assertTrue(expected.equals(DatatypeConverter.printHexBinary(cipherText.toByteArray())));

        long cipherlen = cipherText.readRemaining();
        assertTrue(msglen + 16 == cipherlen); // 16 = CRYPTO_BOX_MACBYTES

        BytesStore message2 = EasyBox.decrypt(cipherText, nonce, alice.publicKey, bob.secretKey);
        assertTrue(Arrays.equals(message.toByteArray(), message2.toByteArray()));
    }

    @Test
    public void testEasyBoxMessageDeterministicShared() {
        BytesStore message = NativeBytesStore
                .from("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et "
                        + "dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip "
                        + "ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu "
                        + "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt "
                        + "mollit anim id est laborum.");

        EasyBox.KeyPair alice = EasyBox.KeyPair.deterministic(123);
        EasyBox.KeyPair bob = EasyBox.KeyPair.deterministic(456);

        EasyBox.SharedKey sharedA = EasyBox.SharedKey.precalc(bob.publicKey, alice.secretKey);
        EasyBox.SharedKey sharedB = EasyBox.SharedKey.precalc(alice.publicKey, bob.secretKey);

        assertEquals(DatatypeConverter.printHexBinary(sharedA.store.toByteArray()), DatatypeConverter.printHexBinary(sharedB.store.toByteArray()));

        EasyBox.Nonce nonce = EasyBox.Nonce.deterministic(789);

        String expected = "970DC924AFCBD44DD20FA514CD328575BD70B483E3C88FE4C20F1F744CE18A8E6D543C3CA3D033B36D9341F32A34A098797762503ECEB8"
                + "C5D24E0C290CA08F5B7A188D3E0E4AB55D767A31F89546171BDE69BC64AFF116DD07A196D9B5D41FF6F7D273B92705450213A2BDCBA3A7"
                + "808C96646E8F0410BF5D2BDC05C71E3A35737D3276400372C0FC53631B445B94F2AB3E4DF55B1BE3B1373BAE36E5A44F0E4B046FF2FCBA"
                + "E8C55E89FDDE6468B0F908176745BA6D1DA788EF08546CC2A675067A6C3A907C765D97EF1C2184B9B748F6081F7168C57BBFABADB0357E"
                + "892A71DCED7867E4D3225A96598FBA9E3771509493C85085DE5ED05A597A45B3B7EF0A3C3FC8A1062AD67C48407C7B7DC0522167FE8295"
                + "DA52A0D311CE995159728FB51F1D2DFEB738442A6FD7C8CA4C9FEB2ED0584D12C5359D0EA558CFC72545CBB821754959DA35F6839866E6"
                + "C04A400E0FE9D8689426E9F1EAE1D77F93026D7B9E19A56353F59EFF980090053C09FB7CCF7438366AD0B9E9DB77042C0491B540646D02"
                + "FE8BB5C3A310B126C932290DD4885915F379A475E52B4025ED495B59BAC92C5487827065B26732A52545E5FCF044DBB3D5F827CA6B7CDF"
                + "E28062EC726BA7A0B0C73C058EDC66485C69663481";

        long msglen = message.readRemaining();

        BytesStore cipherText = EasyBox.encryptShared(message, nonce, sharedA);
        assertTrue(expected.equals(DatatypeConverter.printHexBinary(cipherText.toByteArray())));

        long cipherlen = cipherText.readRemaining();
        assertTrue(msglen + 16 == cipherlen); // 16 = CRYPTO_BOX_MACBYTES

        BytesStore message2 = EasyBox.decryptShared(cipherText, nonce, sharedB);
        assertTrue(Arrays.equals(message.toByteArray(), message2.toByteArray()));
    }

    @Test(expected = IllegalStateException.class)
    public void testDecryptFailsFlippedKeys() {
        BytesStore message = NativeBytesStore.from("Hello World");

        EasyBox.KeyPair alice = EasyBox.KeyPair.generate();
        EasyBox.KeyPair bob = EasyBox.KeyPair.generate();
        EasyBox.Nonce nonce = EasyBox.Nonce.generate();

        BytesStore cipherText = EasyBox.encrypt(message, nonce, bob.publicKey, alice.secretKey);

        // NB: this - intentionally - won't compile. Need to force with the "unsafe" interface
        // EasyBox.decrypt(cipherText, nonce, bob.secretKey, alice.publicKey);
        EasyBox.decrypt(null, cipherText, nonce.store, bob.secretKey.store, alice.publicKey.store);
    }

    @Ignore("Long running")
    @Test
    public void performanceTest() {
        BytesStore message = NativeBytesStore.from("Hello World, this is a short message for testing purposes");
        BytesStore c = null, c2 = null;

        EasyBox.KeyPair kp = EasyBox.KeyPair.generate();
        EasyBox.Nonce nonce = EasyBox.Nonce.generate();

        int runs = 10000;
        for (int t = 0; t < 3; t++) {
            {
                long start = System.nanoTime();
                for (int i = 0; i < runs; i++)
                    c = EasyBox.encrypt(c, message, nonce, kp.publicKey, kp.secretKey);
                long time = (System.nanoTime() - start) / runs;
                System.out.printf("Average time was %,d ns to encrypt, ", time);
            }
            {
                long start = System.nanoTime();
                for (int i = 0; i < runs; i++)
                    c2 = EasyBox.decrypt(c2, c, nonce, kp.publicKey, kp.secretKey);
                long time = (System.nanoTime() - start) / runs;
                System.out.printf("%,d ns to decrypt%n", time);
            }

            nonce.next();
        }
    }

    @Test
    public void performanceTestShared() {
        BytesStore message = NativeBytesStore.from("Hello World, this is a short message for testing purposes");
        BytesStore c = null, c2 = null;

        EasyBox.KeyPair kp = EasyBox.KeyPair.generate();
        EasyBox.SharedKey shared = EasyBox.SharedKey.precalc(kp.publicKey, kp.secretKey);
        EasyBox.Nonce nonce = EasyBox.Nonce.generate();

        int runs = 10000;
        for (int t = 0; t < 3; t++) {
            {
                long start = System.nanoTime();
                for (int i = 0; i < runs; i++)
                    c = EasyBox.encryptShared(c, message, nonce, shared);
                long time = (System.nanoTime() - start) / runs;
                System.out.printf("Average time was %,d ns to encrypt, ", time);
            }
            {
                long start = System.nanoTime();
                for (int i = 0; i < runs; i++)
                    c2 = EasyBox.decryptShared(c2, c, nonce, shared);
                long time = (System.nanoTime() - start) / runs;
                System.out.printf("%,d ns to decrypt%n", time);
            }

            nonce.next();
        }
    }

    @Test
    public void bulkEncryptDecrypt() {
        EasyBox.KeyPair alice = EasyBox.KeyPair.generate();
        EasyBox.KeyPair bob = EasyBox.KeyPair.generate();
        EasyBox.Nonce nonce = EasyBox.Nonce.generate();

        BytesStore message = NativeBytesStore.from("Hello World, this is a short message for testing purposes");

        int runs = 10000;
        for (int t = 0; t < 3; t++) {
            BytesStore cipher = EasyBox.encrypt(message, nonce, bob.publicKey, alice.secretKey);

            BytesStore clear = EasyBox.decrypt(cipher, nonce, alice.publicKey, bob.secretKey);
            assertTrue(Arrays.equals(message.toByteArray(), clear.toByteArray()));

            message = cipher;
            nonce.next();
        }
    }

    @Test
    public void bulkEncryptDecryptShared() {
        EasyBox.KeyPair alice = EasyBox.KeyPair.generate();
        EasyBox.KeyPair bob = EasyBox.KeyPair.generate();

        EasyBox.SharedKey shared = EasyBox.SharedKey.precalc(alice.publicKey, bob.secretKey);
        EasyBox.Nonce nonce = EasyBox.Nonce.generate();

        BytesStore message = NativeBytesStore.from("Hello World, this is a short message for testing purposes");

        int runs = 10000;
        for (int t = 0; t < 3; t++) {
            BytesStore cipher = EasyBox.encryptShared(message, nonce, shared);

            BytesStore clear = EasyBox.decryptShared(cipher, nonce, shared);
            assertTrue(Arrays.equals(message.toByteArray(), clear.toByteArray()));

            message = cipher;
            nonce.next();
        }
    }
}
