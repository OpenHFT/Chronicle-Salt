package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.bytes.NativeBytesStore;
import org.junit.Ignore;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertTrue;

public class EasyBoxTest {

    @Ignore("see https://github.com/OpenHFT/Chronicle-Salt/issues/13")
    @Test
    public void testEasyBox() {
        System.out.println("sodium.version= " + Sodium.SODIUM.sodium_version_string());
        BytesStore message = NativeBytesStore.from("test");
        EasyBox.KeyPair alice = new EasyBox.KeyPair();
        EasyBox.KeyPair bob = new EasyBox.KeyPair();

        BytesStore nonce = EasyBox.nonce();
        BytesStore cypherText = EasyBox.encrypt(null, message, nonce, bob.publicKey, alice.secretKey);

        BytesStore message2 = EasyBox.decrypt(null, cypherText, nonce, alice.publicKey, bob.secretKey);
        assertTrue(Arrays.equals(message.toByteArray(), message2.toByteArray()));

    }
}
