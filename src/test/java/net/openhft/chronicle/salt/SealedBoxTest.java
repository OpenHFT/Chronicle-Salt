package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
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
        assertEquals("2FE57DA347CD62431528DAAC5FBB290730FFF684AFC4CFC2ED90995F58CB3B74",
                DatatypeConverter.printHexBinary(kp.publicKey.toByteArray()));
        kp = new SealedBox.KeyPair(1);
        assertEquals("3B0096025E002244C6900641B4DE39E8FF05CFB3DF99E753F13C1442D5AAFD79",
                DatatypeConverter.printHexBinary(kp.publicKey.toByteArray()));
    }

    @Test
    public void testEncryptDecrypt() {
        SealedBox.KeyPair kp = new SealedBox.KeyPair(1);
//        System.out.println(DatatypeConverter.printHexBinary(kp.secretKey.toByteArray()));
//        System.out.println(DatatypeConverter.printHexBinary(kp.publicKey.toByteArray()));
        BytesStore message = NativeBytesStore.from("Hello World");
        Bytes c = SealedBox.encrypt(null, message, kp.publicKey);

        Bytes message2 = SealedBox.decrypt(null, c, kp.publicKey, kp.secretKey);
//        System.out.println(message2.toHexString());
        assertTrue(Arrays.equals(message.toByteArray(),
                message2.toByteArray()));
    }

    @Test(expected = IllegalStateException.class)
    public void testDecryptFailsFlippedKeys() {
        SealedBox.KeyPair kp = new SealedBox.KeyPair(1);
        BytesStore message = NativeBytesStore.from("Hello World");
        Bytes c = SealedBox.encrypt(null, message, kp.publicKey);

        SealedBox.decrypt(null, c, kp.secretKey, kp.publicKey);
    }

    @Ignore("Long running")
    @Test
    public void performanceTest() {
        SealedBox.KeyPair kp = new SealedBox.KeyPair(1);
        BytesStore message = NativeBytesStore.from("Hello World, this is a short message for testing purposes");
        Bytes c = null, c2 = null;

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
