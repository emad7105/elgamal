package be.heydari.elgamal;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

public interface ReRandAsymmetricBlockCipher {

    /**
     * initialise the cipher.
     *
     * @param forEncryption if true the cipher is initialised for
     *  encryption, if false for decryption.
     * @param param the key and other data required by the cipher.
     */
    public void init(boolean forEncryption, boolean forRandomisation, CipherParameters param);

    /**
     * returns the largest size an input block can be.
     *
     * @return maximum size for an input block.
     */
    public int getInputBlockSize();

    /**
     * returns the maximum size of the block produced by this cipher.
     *
     * @return maximum size of the output block produced by the cipher.
     */
    public int getOutputBlockSize();

    /**
     * process the block of len bytes stored in in from offset inOff.
     *
     * @param in the input data
     * @param inOff offset into the in array where the data starts
     * @param len the length of the block to be processed.
     * @param mode operation mode (encryption, decryption or re-randomisation)
     * @return the resulting byte array of the encryption/decryption process.
     * @exception InvalidCipherTextException data decrypts improperly.
     * @exception DataLengthException the input data is too large for the cipher.
     */
    public byte[] processBlock(byte[] in, int inOff, int len, int mode)
            throws InvalidCipherTextException;
}
