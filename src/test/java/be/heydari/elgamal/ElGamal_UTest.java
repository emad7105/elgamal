package be.heydari.elgamal;

import com.google.common.base.Charsets;
import org.bouncycastle.jcajce.provider.asymmetric.elgamal.BCElGamalPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.elgamal.BCElGamalPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.elgamal.CipherSpi;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import static org.junit.Assert.*;

public class ElGamal_UTest extends TestContext {
    private static final Logger LOGGER = LoggerFactory.getLogger(ElGamal_UTest.class);


    @Ignore
    @Test()
    public void testKeyGen() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ElGamal elGamal = new ElGamal(1024, 5, SECURE_RANDOM_ALG);

        KeyPair keyPair = elGamal.generateKey();

        assertNotNull("Elgamal Key pair", keyPair);
        assertNotNull("ElGamal private key", keyPair.getPrivate());
        assertNotNull("ElGamal public key", keyPair.getPublic());

        LOGGER.info(gson.toJson(keyPair.toString()));
        LOGGER.info(keyPair.getPrivate().toString());
        LOGGER.info(keyPair.getPublic().toString());
    }

    @Test
    public void testKeyGenFast() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ElGamal elGamal = new ElGamal(1024, 5, SECURE_RANDOM_ALG);

        KeyPair keyPair = elGamal.generateKeyFast();

        assertNotNull("Elgamal Key pair", keyPair);
        assertNotNull("ElGamal private key", keyPair.getPrivate());
        assertNotNull("ElGamal public key", keyPair.getPublic());

        BCElGamalPrivateKey secretKey = (BCElGamalPrivateKey) keyPair.getPrivate();
        BCElGamalPublicKey pulicKey = (BCElGamalPublicKey) keyPair.getPublic();


        LOGGER.info(gson.toJson(keyPair));
        LOGGER.info(gson.toJson(keyPair.getPrivate()));
        LOGGER.info(gson.toJson(keyPair.getPublic()));
    }


    @Test
    public void testKeyDataStructureConversions() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        ElGamal elGamal = new ElGamal(1024, 5, SECURE_RANDOM_ALG);

        KeyPair keyPair = elGamal.generateKeyFast();
        byte[] pk = keyPair.getPublic().getEncoded();
        byte[] sk = keyPair.getPrivate().getEncoded();


        byte[] encryptedData = elGamal.encrypt("emad".getBytes(Charsets.UTF_8), elGamal.loadPublicKey(pk));
        byte[] decryptedData = elGamal.decrypt(encryptedData, elGamal.loadPrivateKey(sk));

        assertEquals("emad", new String(decryptedData));
        assertArrayEquals(keyPair.getPrivate().getEncoded(), sk);
        assertArrayEquals(keyPair.getPublic().getEncoded(), pk);
    }


    @Test
    public void encryptDecrypt1024() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        ElGamal elGamal = new ElGamal(1024, 5, SECURE_RANDOM_ALG);
        KeyPair keyPair = elGamal.generateKeyFast();

        PrivateKey esk = keyPair.getPrivate();
        PublicKey epk = keyPair.getPublic();


        // check Dec(Enc(m))=m
        String m = "This is the message!";
        byte[] encryptedM = elGamal.encrypt(m.getBytes(Charsets.UTF_8), epk);

        assertNotNull("Encrypted message", encryptedM);
        assertTrue("encrypted message is not empty", encryptedM.length > 0);

        byte[] decryptedM = elGamal.decrypt(encryptedM, esk);

        assertNotNull("decrypted message", decryptedM);
        assertTrue("decrypted message is not empty", decryptedM.length > 0);
        assertEquals("Dec(Enc(m))=m", new String(decryptedM, Charsets.UTF_8), m);

        LOGGER.info("--------------");
        LOGGER.info("Key size = 1024");
        LOGGER.info("m = " + m);
        LOGGER.info("m.length = " + m.getBytes(Charsets.UTF_8).length + " bytes");
        LOGGER.info("Enc(m).length = " + encryptedM.length + " bytes");
        LOGGER.info("--------------");
    }


    @Test
    public void encryptDecrypt2048() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        ElGamal elGamal = new ElGamal(2048, 5, SECURE_RANDOM_ALG);
        KeyPair keyPair = elGamal.generateKeyFast();

        PrivateKey esk = keyPair.getPrivate();
        PublicKey epk = keyPair.getPublic();


        // check Dec(Enc(m))=m
        String m = "This is the message!";
        byte[] encryptedM = elGamal.encrypt(m.getBytes(Charsets.UTF_8), epk);

        assertNotNull("Encrypted message", encryptedM);
        assertTrue("encrypted message is not empty", encryptedM.length > 0);

        byte[] decryptedM = elGamal.decrypt(encryptedM, esk);

        assertNotNull("decrypted message", decryptedM);
        assertTrue("decrypted message is not empty", decryptedM.length > 0);
        assertEquals("Dec(Enc(m))=m", new String(decryptedM, Charsets.UTF_8), m);

        LOGGER.info("--------------");
        LOGGER.info("Key size = 2048");
        LOGGER.info("m = " + m);
        LOGGER.info("m.length = " + m.getBytes(Charsets.UTF_8).length + " bytes");
        LOGGER.info("Enc(m).length = " + encryptedM.length + " bytes");
        LOGGER.info("--------------");
    }

    @Test
    public void testProbabilisticSecurity() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        ElGamal elGamal = new ElGamal(2048, 5, SECURE_RANDOM_ALG);
        KeyPair keyPair = elGamal.generateKeyFast();

        PrivateKey esk = keyPair.getPrivate();
        PublicKey epk = keyPair.getPublic();

        // check Enc(m) != Enc(m)
        String m = "This is the message!";
        byte[] encryptedM1 = elGamal.encrypt(m.getBytes(Charsets.UTF_8), epk);
        byte[] encryptedM2 = elGamal.encrypt(m.getBytes(Charsets.UTF_8), epk);

        assertTrue("Enc(m) != Enc(m)", !Arrays.equals(encryptedM1, encryptedM2));

        byte[] decryptedM1 = elGamal.decrypt(encryptedM1, esk);
        byte[] decryptedM2 = elGamal.decrypt(encryptedM2, esk);

        assertEquals("Dec(Enc(m))=m  ==  Dec(Enc(m))=m", new String(decryptedM1, Charsets.UTF_8), new String(decryptedM2, Charsets.UTF_8));
    }


    @Test
    public void testReRandomisation() throws NoSuchProviderException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        ElGamal elGamal = new ElGamal(2048, 5, SECURE_RANDOM_ALG);
        KeyPair keyPair = elGamal.generateKeyFast();

        PrivateKey esk = keyPair.getPrivate();
        PublicKey epk = keyPair.getPublic();


        // check Dec(Enc(m))=m
        String m = "This is the message!";
        byte[] encryptedM = elGamal.encrypt(m.getBytes(Charsets.UTF_8), epk);
        byte[] reRandEncryptedM = elGamal.rerand(encryptedM, epk);

        assertNotNull("Encrypted message", encryptedM);
        assertTrue("encrypted message is not empty", encryptedM.length > 0);

        assertNotNull("Encrypted message", reRandEncryptedM);
        assertTrue("encrypted message is not empty", reRandEncryptedM.length > 0);

        byte[] decryptedM = elGamal.decrypt(encryptedM, esk);
        byte[] decryptedReRandM = elGamal.decrypt(reRandEncryptedM, esk);

        assertNotNull("decrypted message", decryptedM);
        assertTrue("decrypted message is not empty", decryptedM.length > 0);
        assertEquals("Dec(Enc(m))=m", new String(decryptedM, Charsets.UTF_8), m);

        assertNotNull("decrypted rerand message", decryptedReRandM);
        assertTrue("decrypted message is not empty", decryptedReRandM.length > 0);
        assertEquals("Dec(Enc(m))=m", new String(decryptedReRandM, Charsets.UTF_8), m);

        LOGGER.info("--------------");
        LOGGER.info("Key size = 2048");
        LOGGER.info("m = " + m);
        LOGGER.info("Enc(m) = " + Hex.toHexString(encryptedM));
        LOGGER.info("ReRand(Enc(m)) = " + Hex.toHexString(reRandEncryptedM));
        LOGGER.info("Dec(Enc(m)) = " + Hex.toHexString(decryptedM));
        LOGGER.info("Dec(ReRand(Enc(m))) = " + Hex.toHexString(decryptedReRandM));
        LOGGER.info("m.length = " + m.getBytes(Charsets.UTF_8).length + " bytes");
        LOGGER.info("Enc(m).length = " + encryptedM.length + " bytes");
        LOGGER.info("ReRand(Enc(m)).length = " + reRandEncryptedM.length + " bytes");
        LOGGER.info("--------------");
    }

    @Test
    public void manyReRands() throws NoSuchProviderException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        int counter = 50;

        ElGamal elGamal = new ElGamal(2048, 5, SECURE_RANDOM_ALG);
        KeyPair keyPair = elGamal.generateKeyFast();
        PrivateKey esk = keyPair.getPrivate();
        PublicKey epk = keyPair.getPublic();

        String m = "This is a message to be encrypted!!!!!";

        // encrypt
        byte[] encM = elGamal.encrypt(m.getBytes(Charsets.UTF_8), epk);
        byte[] rerand = elGamal.rerand(encM, epk);
        byte[] rerand2 = null;

        assertNotEquals("Enc(m) != ReRand(Enc(m))", Hex.toHexString(encM), Hex.toHexString(rerand));


        while(counter != 0) {

            // re-rand
            rerand2 = elGamal.rerand(rerand, epk);
            assertNotEquals("Enc(m) != ReRand(Enc(m))", Hex.toHexString(rerand), Hex.toHexString(rerand2));
            assertNotEquals(encM, rerand2);
            LOGGER.info("rerand: " + Hex.toHexString(rerand));
            LOGGER.info("rerand2: " + Hex.toHexString(rerand2));

            rerand = rerand2;

            // decrypt
            byte[] decM = elGamal.decrypt(rerand2, esk);
            assertEquals("m == Dec(ReRand(... Enc(m) ...))", m, new String(decM, Charsets.UTF_8));

            counter--;
        }


    }



    @Test
    public void testDummy() {
        CipherSpi cipherSpi = new CipherSpi(null);
    }
}