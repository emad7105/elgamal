package be.heydari.elgamal;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.elgamal.ElGamalUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.jce.interfaces.ElGamalKey;
import org.bouncycastle.util.Strings;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Note: A large portion of this code is based BouncyCastle implementation of the ElGamal scheme.
 * https://github.com/bcgit/bc-java/blob/master/prov/src/main/java/org/bouncycastle/jcajce/provider/asymmetric/elgamal/CipherSpi.java
 *
 * @author Emad Heydari Beni, the randization parts
 */
public class ReRandCipherSpi extends BaseCipherSpi {

    private ReRandAsymmetricBlockCipher cipher;
    private AlgorithmParameterSpec paramSpec;
    private AlgorithmParameters engineParams;
    private ErasableOutputStream bOut = new ErasableOutputStream();
    private int opMode;

    public ReRandCipherSpi(
            ReRandAsymmetricBlockCipher engine) {
        cipher = engine;
    }


    protected int engineGetBlockSize() {
        return cipher.getInputBlockSize();
    }

    protected int engineGetKeySize(
            Key key) {
        if (key instanceof ElGamalKey) {
            ElGamalKey k = (ElGamalKey) key;

            return k.getParameters().getP().bitLength();
        } else if (key instanceof DHKey) {
            DHKey k = (DHKey) key;

            return k.getParams().getP().bitLength();
        }

        throw new IllegalArgumentException("not an ElGamal key!");
    }

    protected int engineGetOutputSize(
            int inputLen) {
        return cipher.getOutputBlockSize();
    }

    protected AlgorithmParameters engineGetParameters() {
        if (engineParams == null) {
            if (paramSpec != null) {
                try {
                    engineParams = createParametersInstance("OAEP");
                    engineParams.init(paramSpec);
                } catch (Exception e) {
                    throw new RuntimeException(e.toString());
                }
            }
        }

        return engineParams;
    }

    protected void engineSetMode(
            String mode)
            throws NoSuchAlgorithmException {
        String md = Strings.toUpperCase(mode);

        if (md.equals("NONE") || md.equals("ECB")) {
            return;
        }

        throw new NoSuchAlgorithmException("can't support mode " + mode);
    }

    protected void engineSetPadding(
            String padding)
            throws NoSuchPaddingException {
        String pad = Strings.toUpperCase(padding);

        if (pad.equals("NOPADDING")) {
            cipher = new ReRandElGamalEngine();
        } else {
            throw new NoSuchPaddingException(padding + " unavailable with ElGamal.");
        }
    }

    protected void engineInit(
            int opmode,
            Key key,
            AlgorithmParameterSpec params,
            SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        CipherParameters param;
        this.opMode = opmode;

        if (key instanceof DHPublicKey) {
            param = ElGamalUtil.generatePublicKeyParameter((PublicKey) key);
        } else if (key instanceof DHPrivateKey) {
            param = ElGamalUtil.generatePrivateKeyParameter((PrivateKey) key);
        } else {
            throw new InvalidKeyException("unknown key type passed to ElGamal");
        }


        if (random != null) {
            param = new ParametersWithRandom(param, random);
        }

        switch (opmode) {
            case javax.crypto.Cipher.ENCRYPT_MODE:
            case javax.crypto.Cipher.WRAP_MODE:
                cipher.init(true, false, param);
                break;
            case javax.crypto.Cipher.DECRYPT_MODE:
            case javax.crypto.Cipher.UNWRAP_MODE:
                cipher.init(false, false, param);
                break;
            case -1: // re-rand mode
                cipher.init(false, true, param);
                break;
            default:
                throw new InvalidParameterException("unknown opmode " + opmode + " passed to ElGamal");
        }
    }

    protected void engineInit(
            int opmode,
            Key key,
            AlgorithmParameters params,
            SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("can't handle parameters in ElGamal");
    }

    protected void engineInit(
            int opmode,
            Key key,
            SecureRandom random)
            throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException e) {
            // this shouldn't happen
            throw new InvalidKeyException("Eeeek! " + e.toString(), e);
        }
    }

    protected byte[] engineUpdate(
            byte[] input,
            int inputOffset,
            int inputLen) {
        bOut.write(input, inputOffset, inputLen);
        return null;
    }

    protected int engineUpdate(
            byte[] input,
            int inputOffset,
            int inputLen,
            byte[] output,
            int outputOffset) {
        bOut.write(input, inputOffset, inputLen);
        return 0;
    }


    protected byte[] engineDoFinal(
            byte[] input,
            int inputOffset,
            int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        if (input != null) {
            bOut.write(input, inputOffset, inputLen);
        }

        validateDataBlockSize();

        return getOutput();
    }

    protected int engineDoFinal(
            byte[] input,
            int inputOffset,
            int inputLen,
            byte[] output,
            int outputOffset)
            throws IllegalBlockSizeException, BadPaddingException, ShortBufferException {
        if (outputOffset + engineGetOutputSize(inputLen) > output.length) {
            throw new ShortBufferException("output buffer too short for input.");
        }

        if (input != null) {
            bOut.write(input, inputOffset, inputLen);
        }

        validateDataBlockSize();

        byte[] out = getOutput();

        for (int i = 0; i != out.length; i++) {
            output[outputOffset + i] = out[i];
        }

        return out.length;
    }

    private void validateDataBlockSize() {
        if (cipher instanceof ReRandElGamalEngine) {
            if (bOut.size() > cipher.getInputBlockSize() + 1) {
                throw new ArrayIndexOutOfBoundsException("too much data for ElGamal block");
            }
        } else {
            if (bOut.size() > cipher.getInputBlockSize()) {
                throw new ArrayIndexOutOfBoundsException("too much data for ElGamal block");
            }
        }
    }

    private byte[] getOutput()
            throws BadPaddingException {
        try {
            return cipher.processBlock(bOut.getBuf(), 0, bOut.size(), opMode);
        } catch (InvalidCipherTextException e) {
            throw new BadBlockException("unable to decrypt block", e);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new BadBlockException("unable to decrypt block", e);
        } finally {
            bOut.erase();
        }
    }
}

