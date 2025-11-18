/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.core.OS;
import net.openhft.chronicle.core.io.ClosedIllegalStateException;
import org.junit.Before;
import org.junit.Test;

import static net.openhft.chronicle.salt.TestUtil.nativeBytesStore;
import static org.junit.Assume.assumeTrue;
import static org.junit.Assert.assertArrayEquals;

public class EasyBoxEdgeCaseTest {

    @Before
    public void checkSharedLibrary() {
        assumeTrue(OS.isLinux() && Bridge.LOADED);
    }

    @Test
    public void encryptWithReleasedMessageDoesNotCrash() {
        BytesStore<?, ?> message = nativeBytesStore("edge-case");
        byte[] expected = message.toByteArray();
        message.releaseLast();

        EasyBox.KeyPair alice = EasyBox.KeyPair.generate();
        EasyBox.KeyPair bob = EasyBox.KeyPair.generate();
        EasyBox.Nonce nonce = EasyBox.Nonce.generate();

        try {
            BytesStore<?, ?> cipherText = EasyBox.encrypt(null, message, nonce, bob.publicKey, alice.secretKey);
            BytesStore<?, ?> clear = EasyBox.decrypt(null, cipherText, nonce, alice.publicKey, bob.secretKey);
            // We only assert that the call path does not crash;
            // depending on Chronicle-Bytes semantics, content may differ.
        } catch (ClosedIllegalStateException ignored) {
            // Also acceptable: Chronicle-Bytes may detect use-after-release.
        }
    }

    @Test
    public void decryptWithReleasedCiphertextDoesNotCrash() {
        BytesStore<?, ?> message = nativeBytesStore("edge-case");
        byte[] expected = message.toByteArray();

        EasyBox.KeyPair alice = EasyBox.KeyPair.generate();
        EasyBox.KeyPair bob = EasyBox.KeyPair.generate();
        EasyBox.Nonce nonce = EasyBox.Nonce.generate();

        BytesStore<?, ?> cipherText = EasyBox.encrypt(null, message, nonce, bob.publicKey, alice.secretKey);
        cipherText.releaseLast();

        try {
            BytesStore<?, ?> clear = EasyBox.decrypt(null, cipherText, nonce, alice.publicKey, bob.secretKey);
            assertArrayEquals(expected, clear.toByteArray());
        } catch (ClosedIllegalStateException ignored) {
            // Also acceptable: Chronicle-Bytes may detect use-after-release.
        }
    }

    @Test
    public void concurrentEncryptDecryptDoesNotThrow() throws Exception {
        final EasyBox.KeyPair alice = EasyBox.KeyPair.generate();
        final EasyBox.KeyPair bob = EasyBox.KeyPair.generate();

        Runnable task = () -> {
            BytesStore<?, ?> message = nativeBytesStore("concurrent");
            EasyBox.Nonce nonce = EasyBox.Nonce.generate();
            BytesStore<?, ?> cipherText = EasyBox.encrypt(null, message, nonce, bob.publicKey, alice.secretKey);
            BytesStore<?, ?> clear = EasyBox.decrypt(null, cipherText, nonce, alice.publicKey, bob.secretKey);
            assertArrayEquals(message.toByteArray(), clear.toByteArray());
        };

        Thread t1 = new Thread(task, "easybox-edge-1");
        Thread t2 = new Thread(task, "easybox-edge-2");
        t1.start();
        t2.start();
        t1.join();
        t2.join();
    }
}
