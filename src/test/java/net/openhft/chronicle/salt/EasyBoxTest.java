package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.bytes.NativeBytesStore;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertTrue;

public class EasyBoxTest {
    @Test
    public void testEasyBox() {
        BytesStore message = NativeBytesStore.from("test");
        EasyBox.KeyPair alice = new EasyBox.KeyPair();
        EasyBox.KeyPair bob = new EasyBox.KeyPair();

        BytesStore nonce = EasyBox.nonce();
        BytesStore cypherText = EasyBox.encrypt(null, message, nonce, bob.publicKey, alice.secretKey);

        BytesStore message2 = EasyBox.decrypt(null, cypherText, nonce, alice.publicKey, bob.secretKey);
        assertTrue(Arrays.equals(message.toByteArray(),
                message2.toByteArray()));

    }
}
