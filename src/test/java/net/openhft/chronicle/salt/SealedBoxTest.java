package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.bytes.NativeBytesStore;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SealedBoxTest {

    @Test
    public void tesKeyPair() {
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
}
