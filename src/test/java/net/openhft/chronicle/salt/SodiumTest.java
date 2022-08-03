/*
 * Copyright 2016-2022 chronicle.software
 *
 *       https://chronicle.software
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.openhft.chronicle.salt;

import jnr.ffi.byref.LongLongByReference;
import net.openhft.chronicle.bytes.Bytes;
import net.openhft.chronicle.core.OS;
import org.junit.After;
import org.junit.Test;

import static net.openhft.chronicle.salt.Sodium.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeFalse;

@SuppressWarnings("rawtypes")
public class SodiumTest extends BytesForTesting {
    Bytes<?> bytes = Bytes.allocateDirect(ED25519_SECRETKEY_BYTES);

    @After
    public void tearDown() {
        bytes.releaseLast();
        cleanup();
    }

    @Test
    public void sodium_version_string() {
        System.out.println(SODIUM.sodium_version_string());
    }

    @Test
    public void random_bytes() {
        assumeFalse(OS.isWindows());
        int size = (int) bytes.realCapacity();
        for (int i = 0; i < 10; i++) {
            SODIUM.randombytes(bytes.addressForWrite(0), size);
            checkPseudoRandom(bytes);
        }
    }

    @Test
    public void crypto_box_curve25519xsalsa20poly1305_keypair() {
        assumeFalse(OS.isWindows());

        Bytes<?> secretKey0 = bytesWithZeros(ED25519_SECRETKEY_BYTES);

        assertEquals(0, SODIUM.crypto_box_curve25519xsalsa20poly1305_keypair(secretKey0.addressForWrite(32), secretKey0.addressForWrite(0)));

        checkZeros(secretKey0);

        secretKey0.readPositionRemaining(0, 64);
        System.out.println(secretKey0.toHexString());
        checkPseudoRandom(secretKey0, ED25519_SECRETKEY_BYTES);

        Bytes<?> publicKey = bytesWithZeros(ED25519_PUBLICKEY_BYTES);
        Bytes<?> secretKey = bytesWithZeros(ED25519_SECRETKEY_BYTES);

        assertEquals(0,
                SODIUM.crypto_sign_ed25519_seed_keypair(publicKey.addressForWrite(0), secretKey.addressForWrite(0), secretKey0.addressForRead(0)));
        checkZeros(publicKey);
        checkZeros(secretKey);
        checkPseudoRandom(publicKey, ED25519_PUBLICKEY_BYTES);
        checkPseudoRandom(secretKey, ED25519_SECRETKEY_BYTES);
        // publicKey.readPositionRemaining(0, 32);
        // System.out.println(publicKey.toHexString());
        // secretKey.readPositionRemaining(0, 64);
        // System.out.println(secretKey.toHexString());

    }

    @Test
    public void signAndVerify() {
        assumeFalse(OS.isWindows());
        final String SIGN_PRIVATE = "b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd";

        Bytes<?> publicKey = bytesWithZeros(32);
        Bytes<?> secretKey = bytesWithZeros(64);
        Bytes<?> privateKey = fromHex(SIGN_PRIVATE);
        assertEquals(0,
                SODIUM.crypto_sign_ed25519_seed_keypair(publicKey.addressForWrite(0), secretKey.addressForWrite(0), privateKey.addressForRead(0)));
        publicKey.readPositionRemaining(0, 32);
        secretKey.readPositionRemaining(0, 64);

        Bytes<?> emptyMsg = bytesWithZeros(0);
        Bytes<?> sigAndMsg = bytesWithZeros(ED25519_SECRETKEY_BYTES);

        assertEquals(0, SODIUM.crypto_sign_ed25519(sigAndMsg.addressForWrite(0), new LongLongByReference(0), emptyMsg.addressForRead(0), 0,
                secretKey.addressForRead(0)));

        checkZeros(emptyMsg);
        checkZeros(secretKey);
        checkZeros(sigAndMsg);

        Bytes<?> buffer = bytesWithZeros(ED25519_SECRETKEY_BYTES);

        assertEquals(0, SODIUM.crypto_sign_ed25519_open(buffer.addressForWrite(0), new LongLongByReference(0), sigAndMsg.addressForRead(0), 0 + 64,
                publicKey.addressForRead(0)));

        sigAndMsg.readPositionRemaining(0, 64);
        System.out.println(sigAndMsg.toHexString());
    }

    @Test
    public void signAndVerify2() {
        assumeFalse(OS.isWindows());
        final String SIGN_PRIVATE = "b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd";
        final String SIGN_MESSAGE = "916c7d1d268fc0e77c1bef238432573c39be577bbea0998936add2b50a653171"
                + "ce18a542b0b7f96c1691a3be6031522894a8634183eda38798a0c5d5d79fbd01"
                + "dd04a8646d71873b77b221998a81922d8105f892316369d5224c9983372d2313"
                + "c6b1f4556ea26ba49d46e8b561e0fc76633ac9766e68e21fba7edca93c4c7460" + "376d7f3ac22ff372c18f613f2ae2e856af40";
        final String SIGN_SIGNATURE = "6bd710a368c1249923fc7a1610747403040f0cc30815a00f9ff548a896bbda0b"
                + "4eb2ca19ebcf917f0f34200a9edbad3901b64ab09cc5ef7b9bcc3c40c0ff7509";

        Bytes<?> publicKey = bytesWithZeros(32);
        Bytes<?> secretKey = bytesWithZeros(64);
        Bytes<?> privateKey = fromHex(SIGN_PRIVATE);
        assertEquals(0,
                SODIUM.crypto_sign_ed25519_seed_keypair(publicKey.addressForWrite(0), secretKey.addressForWrite(0), privateKey.addressForRead(0)));
        publicKey.readPositionRemaining(0, 32);
        secretKey.readPositionRemaining(0, 64);
        // System.out.println(publicKey.toHexString());
        // System.out.println(secretKey.toHexString());

        Bytes<?> sigAndMsg2 = fromHex(SIGN_SIGNATURE);
        Bytes<?> message = fromHex(SIGN_MESSAGE);
        Bytes<?> sigAndMsg = fromHex(64 + (SIGN_MESSAGE.length() / 2), "");

        LongLongByReference sigLen = new LongLongByReference(0);
        assertEquals(0, SODIUM.crypto_sign_ed25519(sigAndMsg.addressForWrite(0), sigLen, message.addressForRead(0), (int) message.readRemaining(),
                secretKey.addressForRead(0)));
        checkZeros(sigAndMsg);
        assertEquals(210, sigLen.longValue());
        sigAndMsg.readLimit(64);
        assertEquals(sigAndMsg2.toHexString(), sigAndMsg.toHexString());

        Bytes<?> buffer = bytesWithZeros(210);

        LongLongByReference bufferLen = new LongLongByReference(0);
        assertEquals(0,
                SODIUM.crypto_sign_ed25519_open(buffer.addressForWrite(0), bufferLen, sigAndMsg.addressForRead(0), 210, publicKey.addressForRead(0)));
        assertEquals(210 - 64, bufferLen.longValue());

    }
}