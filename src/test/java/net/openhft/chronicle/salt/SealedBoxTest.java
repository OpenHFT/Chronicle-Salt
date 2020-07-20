package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.bytes.NativeBytesStore;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class SealedBoxTest {

    @Test
    public void testEncryptDecrypt() {
        SealedBox.KeyPair kp = SealedBox.KeyPair.generate();
        BytesStore message = NativeBytesStore.from("Hello World");

        long msglen = message.readRemaining();
        BytesStore c = SealedBox.encrypt(null, message, kp.publicKey);

        long clen = c.readRemaining();
        assertEquals(msglen + 48, clen); // 48 = CRYPTO_BOX_SEALBYTES

        BytesStore message2 = SealedBox.decrypt(null, c, kp.publicKey, kp.secretKey);
        assertArrayEquals(message.toByteArray(), message2.toByteArray());
    }

    @Test
    public void testEncryptDecrypt2() {
        SealedBox.KeyPair kp = SealedBox.KeyPair.generate();
        BytesStore message = NativeBytesStore.from("Hello World");

        BytesStore c = SealedBox.encrypt(message, kp.publicKey);
        BytesStore message2 = SealedBox.decrypt(c, kp.publicKey, kp.secretKey);

        assertArrayEquals(message.toByteArray(), message2.toByteArray());
    }

    @Test
    public void testEncryptDecrypt3() {
        SealedBox.KeyPair kp = SealedBox.KeyPair.generate();
        BytesStore message = NativeBytesStore.from("Hello World");

        BytesStore c = SealedBox.encrypt(null, message, kp.publicKey.store);
        BytesStore message2 = SealedBox.decrypt(null, c, kp.publicKey.store, kp.secretKey.store);

        assertArrayEquals(message.toByteArray(), message2.toByteArray());
    }

    @Test(expected = IllegalStateException.class)
    public void testDecryptFailsFlippedKeys() {
        SealedBox.KeyPair kp = SealedBox.KeyPair.generate();
        BytesStore message = NativeBytesStore.from("Hello World");

        BytesStore c = SealedBox.encrypt(null, message, kp.publicKey);
        // NB: this - intentionally - won't compile. Need to force with the "unsafe" interface
        // SealedBox.decrypt(cipherText, kp.secretKey, kp.publicKey);
        SealedBox.decrypt(null, c, kp.secretKey.store, kp.publicKey.store);
    }

    @Ignore("Long running")
    @Test
    public void performanceTest() {
        SealedBox.KeyPair kp = SealedBox.KeyPair.generate();
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
