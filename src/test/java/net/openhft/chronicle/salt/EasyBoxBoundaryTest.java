/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.core.OS;
import org.junit.Before;
import org.junit.Test;

import static net.openhft.chronicle.salt.TestUtil.nativeBytesStore;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assume.assumeTrue;

public class EasyBoxBoundaryTest {

    @Before
    public void checkSharedLibrary() {
        assumeTrue(OS.isLinux() && Bridge.LOADED);
    }

    @Test
    public void encryptAndDecryptEmptyMessage() {
        BytesStore<?, ?> message = nativeBytesStore("");

        EasyBox.KeyPair alice = EasyBox.KeyPair.generate();
        EasyBox.KeyPair bob = EasyBox.KeyPair.generate();
        EasyBox.Nonce nonce = EasyBox.Nonce.generate();

        BytesStore<?, ?> cipherText = EasyBox.encrypt(null, message, nonce, bob.publicKey, alice.secretKey);
        BytesStore<?, ?> clear = EasyBox.decrypt(null, cipherText, nonce, alice.publicKey, bob.secretKey);

        assertArrayEquals(message.toByteArray(), clear.toByteArray());
    }

    @Test
    public void encryptAndDecryptLargeMessage() {
        StringBuilder sb = new StringBuilder(1024 * 1024);
        while (sb.length() < 1024 * 1024) {
            sb.append("Chronicle-Salt-large-message-");
        }
        BytesStore<?, ?> message = nativeBytesStore(sb.toString());

        EasyBox.KeyPair alice = EasyBox.KeyPair.generate();
        EasyBox.KeyPair bob = EasyBox.KeyPair.generate();
        EasyBox.Nonce nonce = EasyBox.Nonce.generate();

        BytesStore<?, ?> cipherText = EasyBox.encrypt(null, message, nonce, bob.publicKey, alice.secretKey);
        BytesStore<?, ?> clear = EasyBox.decrypt(null, cipherText, nonce, alice.publicKey, bob.secretKey);

        assertArrayEquals(message.toByteArray(), clear.toByteArray());
    }
}
