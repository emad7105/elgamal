package be.heydari.elgamal;

import com.sun.org.slf4j.internal.Logger;
import com.sun.org.slf4j.internal.LoggerFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ElGamalKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.BigIntegers;


import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Note: A large portion of this code is based BouncyCastle implementation of the ElGamal scheme.
 * https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/crypto/engines/ElGamalEngine.java
 * <p>
 * this does your basic ElGamal algorithm.
 */
public class ReRandElGamalEngine implements be.heydari.elgamal.ReRandAsymmetricBlockCipher {
    private static final Logger LOGGER = LoggerFactory.getLogger(ReRandElGamalEngine.class);


    private ElGamalKeyParameters key;
    private SecureRandom random;
    private boolean forEncryption;
    private boolean forReRandomisation;
    private int bitSize;

    private static final BigInteger ZERO = BigInteger.valueOf(0);
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    /**
     * initialise the ElGamal engine.
     *
     * @param forEncryption true if we are encrypting, false otherwise.
     * @param param         the necessary ElGamal key parameters.
     */
    public void init(
            boolean forEncryption,
            boolean forReRandomisation,
            CipherParameters param) {
        if (param instanceof ParametersWithRandom) {
            ParametersWithRandom p = (ParametersWithRandom) param;

            this.key = (ElGamalKeyParameters) p.getParameters();
            this.random = p.getRandom();
        } else {
            this.key = (ElGamalKeyParameters) param;
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }

        this.forEncryption = forEncryption;
        this.forReRandomisation = forReRandomisation;

        BigInteger p = key.getParameters().getP();

        bitSize = p.bitLength();

        if (forEncryption) {
            if (!(key instanceof ElGamalPublicKeyParameters)) {
                throw new IllegalArgumentException("ElGamalPublicKeyParameters are required for encryption.");
            }
        } else if (forReRandomisation) {
            if (!(key instanceof ElGamalPublicKeyParameters)) {
                throw new IllegalArgumentException("ElGamalPublicKeyParameters are required for re-randomization.");
            }
        } else {
            if (!(key instanceof ElGamalPrivateKeyParameters)) {
                throw new IllegalArgumentException("ElGamalPrivateKeyParameters are required for decryption.");
            }
        }
    }

    /**
     * Return the maximum size for an input block to this engine.
     * For ElGamal this is always one byte less than the size of P on
     * encryption, and twice the length as the size of P on decryption.
     *
     * @return maximum size for an input block.
     */
    public int getInputBlockSize() {
        if (forEncryption) {
            return (bitSize - 1) / 8;
        }

        if (forReRandomisation) {
            return 2 * ((bitSize + 7) / 8);
        }

        return 2 * ((bitSize + 7) / 8);
    }

    /**
     * Return the maximum size for an output block to this engine.
     * For ElGamal this is always one byte less than the size of P on
     * decryption, and twice the length as the size of P on encryption.
     *
     * @return maximum size for an output block.
     */
    public int getOutputBlockSize() {
        if (forEncryption) {
            return 2 * ((bitSize + 7) / 8);
        }

        if (forReRandomisation) {
            return 2 * ((bitSize + 7) / 8);
        }

        return (bitSize - 1) / 8;
    }

    /**
     * Process a single block using the basic ElGamal algorithm.
     *
     * @param in    the input array.
     * @param inOff the offset into the input buffer where the data starts.
     * @param inLen the length of the data to be processed.
     * @return the result of the ElGamal process.
     * @throws DataLengthException the input block is too large.
     */
    public byte[] processBlock(
            byte[] in,
            int inOff,
            int inLen,
            int mode) {
        if (key == null) {
            throw new IllegalStateException("ElGamal engine not initialised");
        }

        int maxLength = forEncryption
                ? (bitSize - 1 + 7) / 8
                : getInputBlockSize();

        if (inLen > maxLength) {
            throw new DataLengthException("input too large for ElGamal cipher.\n");
        }

        BigInteger p = key.getParameters().getP();

        if (key instanceof ElGamalPrivateKeyParameters && (mode == ElGamalMode.DECRYPT)) // decryption
        {
            byte[] in1 = new byte[inLen / 2];
            byte[] in2 = new byte[inLen / 2];

            System.arraycopy(in, inOff, in1, 0, in1.length);
            System.arraycopy(in, inOff + in1.length, in2, 0, in2.length);

            BigInteger gamma = new BigInteger(1, in1);
            BigInteger phi = new BigInteger(1, in2);

            ElGamalPrivateKeyParameters priv = (ElGamalPrivateKeyParameters) key;
            // a shortcut, which generally relies on p being prime amongst other things.
            // if a problem with this shows up, check the p and g values!
            BigInteger m = gamma.modPow(p.subtract(ONE).subtract(priv.getX()), p).multiply(phi).mod(p);

            return BigIntegers.asUnsignedByteArray(m);
        } else if (mode == ElGamalMode.ENCRYPT) // encryption
        {
            byte[] block;
            if (inOff != 0 || inLen != in.length) {
                block = new byte[inLen];

                System.arraycopy(in, inOff, block, 0, inLen);
            } else {
                block = in;
            }

            BigInteger input = new BigInteger(1, block);

            if (input.compareTo(p) >= 0) {
                throw new DataLengthException("input too large for ElGamal cipher.\n");
            }

            ElGamalPublicKeyParameters pub = (ElGamalPublicKeyParameters) key;

            int pBitLength = p.bitLength();
            BigInteger k = BigIntegers.createRandomBigInteger(pBitLength, random);

            while (k.equals(ZERO) || (k.compareTo(p.subtract(TWO)) > 0)) {
                k = BigIntegers.createRandomBigInteger(pBitLength, random);
            }

            BigInteger g = key.getParameters().getG();
            BigInteger gamma = g.modPow(k, p);
            BigInteger phi = input.multiply(pub.getY().modPow(k, p)).mod(p);

            byte[] out1 = gamma.toByteArray();
            byte[] out2 = phi.toByteArray();
            byte[] output = new byte[this.getOutputBlockSize()];

            if (out1.length > output.length / 2) {
                System.arraycopy(out1, 1, output, output.length / 2 - (out1.length - 1), out1.length - 1);
            } else {
                System.arraycopy(out1, 0, output, output.length / 2 - out1.length, out1.length);
            }

            if (out2.length > output.length / 2) {
                System.arraycopy(out2, 1, output, output.length - (out2.length - 1), out2.length - 1);
            } else {
                System.arraycopy(out2, 0, output, output.length - out2.length, out2.length);
            }

            return output;
        } else { // re-randomisation (mode == -1)
            byte[] in1 = new byte[inLen / 2];
            byte[] in2 = new byte[inLen / 2];

            System.arraycopy(in, inOff, in1, 0, in1.length);
            System.arraycopy(in, inOff + in1.length, in2, 0, in2.length);

            // g^k
            BigInteger gamma = new BigInteger(1, in1);
            // mg^xk
            BigInteger phi = new BigInteger(1, in2);

            ElGamalPublicKeyParameters pub = (ElGamalPublicKeyParameters) key;
            BigInteger y = pub.getY();
            BigInteger g = pub.getParameters().getG();

            int pBitLength = p.bitLength();
            BigInteger r = BigIntegers.createRandomBigInteger(pBitLength, random);

            while (r.equals(ZERO) || (r.compareTo(p.subtract(TWO)) > 0)) {
                r = BigIntegers.createRandomBigInteger(pBitLength, random);
            }

            // re-randomise
            /*
                out1 <- gamma(in1) * g^r
                out2 <- phi(in2) * y^r

                out1 <- g^k * g^r = g^(k+r)
                out2 <- g^xk * m * g^xr = g^x(k+r) * m
            */

            BigInteger rerandGamma = gamma.multiply(g.modPow(r, p)).mod(p);
            BigInteger rerandPhi = phi.multiply(y.modPow(r, p)).mod(p);


            byte[] out1 = rerandGamma.toByteArray();
            byte[] out2 = rerandPhi.toByteArray();
            byte[] output = new byte[this.getOutputBlockSize()];

            if (out1.length > output.length / 2) {
                System.arraycopy(out1, 1, output, output.length / 2 - (out1.length - 1), out1.length - 1);
            } else {
                System.arraycopy(out1, 0, output, output.length / 2 - out1.length, out1.length);
            }

            if (out2.length > output.length / 2) {
                System.arraycopy(out2, 1, output, output.length - (out2.length - 1), out2.length - 1);
            } else {
                System.arraycopy(out2, 0, output, output.length - out2.length, out2.length);
            }

            return output;
        }
    }

    public class ElGamalMode {
        public static final int ENCRYPT = 1;
        public static final int DECRYPT = 2;
        public static final int RERAND = -1;
    }
}
