package be.kuleuven.crypto.elgamal;

import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author Emad Heydari Beni
 */
public class ElGamal {

    public static final String ALG = "ElGamal";

    private SecureRandom random;
    private Integer size;
    private Integer certainty;

    /**
     * @param size            size of the big integers, e.g. 1024, 2048
     * @param certainty       the probability of a number being prime, 10, 16
     * @param secureRandomAlg secure random algorithm name
     */
    public ElGamal(int size, int certainty, String secureRandomAlg) {
        this.size = size;
        this.certainty = certainty;
        addSecurityProvider(secureRandomAlg);
    }

    /**
     * it finds a safe prime p where p = 2*q + 1, where p and q are prime.
     * Note: can take a while...
     *
     * @return a pair of ElGamal key pair
     */
    public KeyPair generateKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALG, "BC");

        // generate params
        ElGamalParametersGenerator elGamalParametersGenerator = new ElGamalParametersGenerator();
        elGamalParametersGenerator.init(getSize(), getCertainty(), getRandom());
        ElGamalParameters elGamalParameters = elGamalParametersGenerator.generateParameters();

        AlgorithmParameterSpec algorithmParameterSpec = new ElGamalParameterSpec(elGamalParameters.getP(), elGamalParameters.getG());
        keyGen.initialize(algorithmParameterSpec);


        return keyGen.genKeyPair();
    }

    public KeyPair generateKeyFast() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALG, "BC");
        keyGen.initialize(getSize(), getRandom());
        return keyGen.genKeyPair();
    }

    public byte[] encrypt(byte[] data, Key publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
//        Cipher cipher = Cipher.getInstance("ElGamal", "BC");
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        return cipher.doFinal(data);
        ReRandCipherSpi reRandCipherSpi = new ReRandCipherSpi(new ReRandElGamalEngine());
        reRandCipherSpi.engineInit(ReRandElGamalEngine.ElGamalMode.ENCRYPT, publicKey, getRandom());
        return reRandCipherSpi.engineDoFinal(data, 0, data.length);
    }

    public byte[] decrypt(byte[] encryptedData, Key privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
//        Cipher cipher = Cipher.getInstance("ElGamal", "BC");
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//        return cipher.doFinal(encryptedData);
        ReRandCipherSpi reRandCipherSpi = new ReRandCipherSpi(new ReRandElGamalEngine());
        reRandCipherSpi.engineInit(ReRandElGamalEngine.ElGamalMode.DECRYPT, privateKey, getRandom());
        return reRandCipherSpi.engineDoFinal(encryptedData, 0, encryptedData.length);
    }

    public byte[] decrypt(byte[] encryptedData, byte[] privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        return decrypt(encryptedData, loadPrivateKey(privateKey));
    }

    /**
     * Note: this function works on the no-padding setting! (The others are not tested)
     */
    public byte[] rerand(byte[] encryptedData, Key publicKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        ReRandCipherSpi reRandCipherSpi = new ReRandCipherSpi(new ReRandElGamalEngine());
        reRandCipherSpi.engineInit(ReRandElGamalEngine.ElGamalMode.RERAND, publicKey, getRandom());
        return reRandCipherSpi.engineDoFinal(encryptedData, 0, encryptedData.length);
    }

    public byte[] rerand(byte[] encryptedData, byte[] publicKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, NoSuchAlgorithmException {
        return rerand(encryptedData, loadPublicKey(publicKey));
    }

    public PublicKey loadPublicKey(String pkInHex) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return loadPublicKey(Hex.decode(pkInHex));
    }

    public PublicKey loadPublicKey(byte[] pk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec spec2 =
                new X509EncodedKeySpec(pk);
        KeyFactory kf2;
        kf2 = KeyFactory.getInstance(ALG);
        return kf2.generatePublic(spec2);
    }

    public PrivateKey loadPrivateKey(String prInHex) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return loadPrivateKey(Hex.decode(prInHex));
    }

    public PrivateKey loadPrivateKey(byte[] pr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec spec1 =
                new PKCS8EncodedKeySpec(pr);
        KeyFactory kf1;
        kf1 = KeyFactory.getInstance(ALG);
        return kf1.generatePrivate(spec1);
    }

    private void addSecurityProvider(String secureRandomAlg) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            random = SecureRandom.getInstance(secureRandomAlg);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


    public SecureRandom getRandom() {
        return random;
    }

    public void setRandom(SecureRandom random) {
        this.random = random;
    }

    public Integer getSize() {
        return size;
    }

    public void setSize(Integer size) {
        this.size = size;
    }

    public Integer getCertainty() {
        return certainty;
    }

    public void setCertainty(Integer certainty) {
        this.certainty = certainty;
    }
}
