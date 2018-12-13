package net.openhft.chronicle.salt;

import net.openhft.chronicle.bytes.BytesStore;
import net.openhft.chronicle.bytes.NativeBytesStore;
import org.junit.Ignore;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SignatureTest {

    @Test
    public void testKeyPairShortSeed() {
        Signature.KeyPair kp = Signature.KeyPair.deterministic(123);

        assertEquals( "9B37EDB59199672751E762C5200873E98619EB210AD241862940C740929AF814",
                DatatypeConverter.printHexBinary(kp.publicKey.store.toByteArray()) );
    }

    @Test
    public void testKeyPairLongSeed() {
        BytesStore seed = NativeBytesStore.from("01234567890123456789012345678901");
        Signature.KeyPair kp = Signature.KeyPair.deterministic(seed);

        assertEquals("7BC3079518ED11DA0336085BF6962920FF87FB3C4D630A9B58CB6153674F5DD6",
                DatatypeConverter.printHexBinary(kp.publicKey.store.toByteArray()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testKeyPairDeterministicTooShort() {
        BytesStore seed = NativeBytesStore.from("0123456789012345678901234567");
        Signature.KeyPair kp = Signature.KeyPair.deterministic(seed);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testKeyPairDeterministicTooLong() {
        BytesStore seed = NativeBytesStore.from("0123456789012345678901234567890123456789");
        Signature.KeyPair kp = Signature.KeyPair.deterministic(seed);
    }

    @Test
    public void testSignVerify()
    {
        BytesStore message = NativeBytesStore.from( "test message" );

        Signature.KeyPair keys = Signature.KeyPair.generate();

        BytesStore signed = Signature.sign( null, message, keys.secretKey );
        BytesStore unsigned = Signature.verify( null, signed, keys.publicKey);

        assertTrue( Arrays.equals( message.toByteArray(), unsigned.toByteArray() ));
    }

    @Test
    public void testSignVerify2()
    {
        BytesStore message = NativeBytesStore.from( "test message" );

        Signature.KeyPair keys = Signature.KeyPair.generate();

        BytesStore signed = Signature.sign( message, keys.secretKey );
        BytesStore unsigned = Signature.verify( signed, keys.publicKey);

        assertTrue( Arrays.equals( message.toByteArray(), unsigned.toByteArray() ));
    }

    @Test
    public void testSignVerify3()
    {
        BytesStore message = NativeBytesStore.from( "test message" );

        Signature.KeyPair keys = Signature.KeyPair.generate();

        BytesStore signed = Signature.sign( null, message, keys.secretKey.store );
        BytesStore unsigned = Signature.verify( null, signed, keys.publicKey.store);

        assertTrue( Arrays.equals( message.toByteArray(), unsigned.toByteArray() ));
    }

    @Test
    public void testSignatureDeterministic() {
        BytesStore message = NativeBytesStore.from(
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et " +
                "dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip " +
                "ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu " +
                "fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt " +
                "mollit anim id est laborum.");

        Signature.KeyPair keys = Signature.KeyPair.deterministic(123);

        String expected = new String(
                "1F02DE4C6263043CD7F6071263FA22BA7330D4F6383F15E28C7020E2C9D4A46F5B896FCBC9020B43741BBF1830246F4B7BF"
                  +"5425200DC5405F1A1DE8AF241640A4C6F72656D20697073756D20646F6C6F722073697420616D65742C20636F6E73656374"
                  +"657475722061646970697363696E6720656C69742C2073656420646F20656975736D6F642074656D706F7220696E6369646"
                  +"964756E74207574206C61626F726520657420646F6C6F7265206D61676E6120616C697175612E20557420656E696D206164"
                  +"206D696E696D2076656E69616D2C2071756973206E6F737472756420657865726369746174696F6E20756C6C616D636F206"
                  +"C61626F726973206E69736920757420616C697175697020657820656120636F6D6D6F646F20636F6E7365717561742E2044"
                  +"756973206175746520697275726520646F6C6F7220696E20726570726568656E646572697420696E20766F6C75707461746"
                  +"52076656C697420657373652063696C6C756D20646F6C6F726520657520667567696174206E756C6C612070617269617475"
                  +"722E204578636570746575722073696E74206F6363616563617420637570696461746174206E6F6E2070726F6964656E742"
                  +"C2073756E7420696E2063756C706120717569206F666669636961206465736572756E74206D6F6C6C697420616E696D2069"
                  +"6420657374206C61626F72756D2E");

        long msglen = message.readRemaining();

        BytesStore signed = Signature.sign(message, keys.secretKey);
        assertTrue( expected.equals( DatatypeConverter.printHexBinary(signed.toByteArray()) ));

        long signedlen = signed.readRemaining();
        assertTrue( msglen + 64 == signedlen ); // 16 = CRYPTO_BOX_MACBYTES

        BytesStore message2 = Signature.verify( signed, keys.publicKey );
        assertTrue(Arrays.equals(message.toByteArray(), message2.toByteArray()));
    }

    @Test(expected = IllegalStateException.class)
    public void testVerifyFailsFlippedKeys() {
        BytesStore message = NativeBytesStore.from("Hello World");

        Signature.KeyPair keys = Signature.KeyPair.generate();

        BytesStore signed = Signature.sign(message, keys.secretKey);

        // NB: this - intentionally - won't compile. Need to force with the "unsafe" interface
        // Signature.verify(signed, keys.publicKey);
        Signature.verify(null, signed, keys.secretKey.store );
    }

    @Test
    public void testMultiPart()
    {
        BytesStore message1 = NativeBytesStore.from( "Message part1");
        BytesStore message2 = NativeBytesStore.from( "Message part2");
        BytesStore message3 = NativeBytesStore.from( "Message part3");

        Signature.KeyPair keys = Signature.KeyPair.deterministic(123);

        Signature.MultiPart multi = new Signature.MultiPart();
        multi.add( message1 );
        multi.add( message2 );
        multi.add( message3 );
        BytesStore signature = multi.sign( keys.secretKey );

        assertEquals( "FE7EBF26E92709DB6DC2953F93E757883627CA0956685392E2173774A051ABF5"
                              +"12CB6791D42F13F5C672B226731EF9263284502BC64BD6FDC8858B4BB49CA006",
                DatatypeConverter.printHexBinary(signature.toByteArray()));

        Signature.MultiPart recv = new Signature.MultiPart();
        recv.add( message1 );
        recv.add( message2 );
        recv.add( message3 );
        recv.verify( signature, keys.publicKey );
    }

    @Test
    public void testMultiPart2()
    {
        BytesStore message1 = NativeBytesStore.from( "Message part1");
        BytesStore message2 = NativeBytesStore.from( "Message part2");
        BytesStore message3 = NativeBytesStore.from( "Message part3");

        Signature.KeyPair keys = Signature.KeyPair.deterministic(123);

        Signature.MultiPart multi = new Signature.MultiPart();
        multi.add( message1 );
        multi.add( message2 );
        multi.add( message3 );
        BytesStore signature = multi.sign( keys.secretKey.store );

        assertEquals( "FE7EBF26E92709DB6DC2953F93E757883627CA0956685392E2173774A051ABF5"
                              +"12CB6791D42F13F5C672B226731EF9263284502BC64BD6FDC8858B4BB49CA006",
                DatatypeConverter.printHexBinary(signature.toByteArray()));

        Signature.MultiPart recv = new Signature.MultiPart();
        recv.add( message1 );
        recv.add( message2 );
        recv.add( message3 );
        recv.verify( signature, keys.publicKey.store );
    }

    @Test
    public void extractTest()
    {
        Signature.KeyPair keys = Signature.KeyPair.deterministic(123);

        BytesStore seed = keys.secretKey.extractSeed();
        assertEquals( "7B00000000000000000000000000000000000000000000000000000000000000",
                DatatypeConverter.printHexBinary(seed.toByteArray() ) );

        BytesStore pk = keys.secretKey.extractPublicKey();
        assertEquals( "9B37EDB59199672751E762C5200873E98619EB210AD241862940C740929AF814",
                DatatypeConverter.printHexBinary(pk.toByteArray() ) );

        assertTrue( Arrays.equals( keys.publicKey.store.toByteArray(), pk.toByteArray() ) );
    }

    @Test
    public void extractTest2()
    {
        BytesStore seed = NativeBytesStore.from( "01234567890123456789012345678901" );
        Signature.KeyPair keys = Signature.KeyPair.deterministic(seed);

        BytesStore seed2 = keys.secretKey.extractSeed();
        assertEquals( "3031323334353637383930313233343536373839303132333435363738393031",
                DatatypeConverter.printHexBinary(seed2.toByteArray() ) );

        BytesStore pk = keys.secretKey.extractPublicKey();
        assertEquals( "7BC3079518ED11DA0336085BF6962920FF87FB3C4D630A9B58CB6153674F5DD6",
                DatatypeConverter.printHexBinary(pk.toByteArray() ) );

        assertTrue( Arrays.equals( keys.publicKey.store.toByteArray(), pk.toByteArray() ) );
    }
}
