package net.openhft.chronicle.salt;


import net.openhft.chronicle.bytes.Bytes;
import org.junit.After;
import org.junit.Test;

/**
 * Copyright 2013 Bruno Oliveira, and individual contributors
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

@SuppressWarnings("rawtypes")
public class SigningTest extends BytesForTesting {

    public static final String SECRET_KEY = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389";
    public static final String SIGN_PRIVATE = "b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd";
    public static final String SIGN_MESSAGE = "916c7d1d268fc0e77c1bef238432573c39be577bbea0998936add2b50a653171"
            + "ce18a542b0b7f96c1691a3be6031522894a8634183eda38798a0c5d5d79fbd01" + "dd04a8646d71873b77b221998a81922d8105f892316369d5224c9983372d2313"
            + "c6b1f4556ea26ba49d46e8b561e0fc76633ac9766e68e21fba7edca93c4c7460" + "376d7f3ac22ff372c18f613f2ae2e856af40";
    public static final String SIGN_SIGNATURE = "6bd710a368c1249923fc7a1610747403040f0cc30815a00f9ff548a896bbda0b"
            + "4eb2ca19ebcf917f0f34200a9edbad3901b64ab09cc5ef7b9bcc3c40c0ff7509";
    public static final String SIGN_PUBLIC = "77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb";
    private static final int SIGNATURE_SIZE = 512 / Byte.SIZE;

    @After
    public void tearDown() {
        cleanup();
    }

    @Test
    public void testSignMessageAsBytes() throws Exception {
        Bytes seed = fromHex(SIGN_PRIVATE);
        Bytes secretKey = bytesWithZeros(32 * 2);
        Bytes publicKey = bytesWithZeros(32);
        Ed25519.privateToPublicAndSecret(publicKey, secretKey, seed);

        Bytes message = fromHex(SIGN_MESSAGE);
        Bytes signExpected = fromHex(SIGN_SIGNATURE);
        Bytes signedMsg = fromHex(SIGNATURE_SIZE, SIGN_MESSAGE);
        signedMsg.clear();
        Ed25519.sign(signedMsg, message, secretKey);
        compare(signExpected, signedMsg, SIGNATURE_SIZE);

    }

    // @Test
    // public void testSignMessageAsHex() throws Exception {
    // SigningKey key = new SigningKey(SIGN_PRIVATE, HEX);
    // String signature = key.sign(SIGN_MESSAGE, HEX);
    // assertEquals("Message sign has failed", SIGN_SIGNATURE, signature);
    // }
    //
    // @Test
    // public void testSerializesToHex() throws Exception {
    // try {
    // SigningKey key = new SigningKey(SIGN_PRIVATE, HEX);
    // assertEquals("Correct sign key expected", SIGN_PRIVATE, key.toString());
    // } catch (Exception e) {
    // fail("Should return a valid key size");
    // }
    // }
    //
    // @Test
    // public void testSerializesToBytes() throws Exception {
    // try {
    // byte[] rawKey = HEX.decode(SIGN_PRIVATE);
    // SigningKey key = new SigningKey(SIGN_PRIVATE, HEX);
    // assertTrue("Correct sign key expected", Arrays.equals(rawKey,
    // key.toBytes()));
    // } catch (Exception e) {
    // fail("Should return a valid key size");
    // }
    // }
    //
    // @Test
    // public void testAccessVerifyKey() {
    // SigningKey key = new SigningKey(SIGN_PRIVATE, HEX);
    // VerifyKey v = key.getVerifyKey();
    // assertEquals(v.toString(), SIGN_PUBLIC);
    // }
    //
    // @Test
    // public void testRoundTrip() {
    // SigningKey key = new SigningKey(SIGN_PRIVATE, HEX);
    // String signature = key.sign(SIGN_MESSAGE, HEX);
    // key.getVerifyKey().verify(SIGN_MESSAGE, signature, HEX);
    // }
}