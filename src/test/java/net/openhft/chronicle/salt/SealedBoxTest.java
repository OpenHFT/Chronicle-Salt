package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.bytes.NativeBytesStore;
import org.junit.Ignore;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SealedBoxTest {

    @Test
    public void testKeyPair() {
        SealedBox.KeyPair kp = new SealedBox.KeyPair(0);

        assertEquals("5BF55C73B82EBE22BE80F3430667AF570FAE2556A6415E6B30D4065300AA947D",
                DatatypeConverter.printHexBinary(kp.publicKey.toByteArray()));
        kp = new SealedBox.KeyPair(1);
        assertEquals("0C7B17FB4925EF41E25D75966AEA10BE2A96458DFF8CC906B4BC5312C0040528",
                DatatypeConverter.printHexBinary(kp.publicKey.toByteArray()));
    }

    @Test
    public void testEncryptDecrypt() {
        SealedBox.KeyPair kp = new SealedBox.KeyPair(1);
        // System.out.println(DatatypeConverter.printHexBinary(kp.secretKey.toByteArray()));
        // System.out.println(DatatypeConverter.printHexBinary(kp.publicKey.toByteArray()));
        BytesStore message = NativeBytesStore.from("Hello World");

        BytesStore c = SealedBox.encrypt(null, message, kp.publicKey);
        BytesStore message2 = SealedBox.decrypt(null, c, kp.publicKey, kp.secretKey);

        // System.out.println(message2.toHexString());
        assertTrue(Arrays.equals(message.toByteArray(), message2.toByteArray()));
    }

    @Test
    public void testEncryptDecrypt2() {
        SealedBox.KeyPair kp = new SealedBox.KeyPair(123);
        BytesStore message = NativeBytesStore.from("Hello World");

        BytesStore c = SealedBox.encrypt(message, kp.publicKey);
        BytesStore message2 = SealedBox.decrypt(c, kp.publicKey, kp.secretKey);

        assertTrue(Arrays.equals(message.toByteArray(), message2.toByteArray()));
    }

    @Test(expected = IllegalStateException.class)
    public void testDecryptFailsFlippedKeys() {
        SealedBox.KeyPair kp = new SealedBox.KeyPair(1);
        BytesStore message = NativeBytesStore.from("Hello World");

        BytesStore c = SealedBox.encrypt(null, message, kp.publicKey);
        SealedBox.decrypt(null, c, kp.secretKey, kp.publicKey);
    }

    @Test(expected = IllegalStateException.class)
    public void testDecryptFailsFlippedKeys2() {
        SealedBox.KeyPair kp = new SealedBox.KeyPair(123);
        BytesStore message = NativeBytesStore.from("Hello World");

        BytesStore c = SealedBox.encrypt(message, kp.publicKey);
        SealedBox.decrypt(c, kp.secretKey, kp.publicKey);
    }

    @Ignore("Long running")
    @Test
    public void performanceTest() {
        SealedBox.KeyPair kp = new SealedBox.KeyPair(1);
        BytesStore message = NativeBytesStore.from("Hello World, this is a short message for testing purposes");
        BytesStore c = null, c2 = null;

        int runs = 10000;
        for (int t = 0; t < 3; t++) {
            {
                long start = System.nanoTime();
                for (int i = 0; i < runs; i++)
                    c = SealedBox.encrypt(c, message, kp.publicKey);
                long time = (System.nanoTime() - start) / runs;
                System.out.printf("Average time was %,d ns to encrypt, ", time);
            }
            {
                long start = System.nanoTime();
                for (int i = 0; i < runs; i++)
                    c2 = SealedBox.decrypt(c2, c, kp.publicKey, kp.secretKey);
                long time = (System.nanoTime() - start) / runs;
                System.out.printf("%,d ns to decrypt%n", time);
            }
        }

    }
}
