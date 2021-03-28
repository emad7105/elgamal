package be.kuleuven.crypto;

import be.kuleuven.crypto.coprf.CoPRF;
import be.kuleuven.crypto.coprf.implementations.ConvertImpl;
import be.kuleuven.crypto.coprf.implementations.EvalImpl;
import be.kuleuven.crypto.coprf.implementations.MainImpl;
import be.kuleuven.crypto.ec.MapToCurveSecP256k1;
import be.kuleuven.crypto.elgamal.ECElGamal;
import be.kuleuven.crypto.standard.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import junit.framework.AssertionFailedError;
import junit.framework.TestCase;
import org.junit.Ignore;

import java.security.SecureRandom;
import java.util.Arrays;

@Ignore
public class TestContext extends TestCase {

    public final static String SECURE_RANDOM_ALG = "NativePRNG"; // SHA1PRNG
    public final static Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public MapToCurveSecP256k1 mapToCurveSecP256k1;
    public CryptoPrimitives cryptoPrimitives;
    public CoPRF coPRF;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        HMAC hmac = new HMAC(SECURE_RANDOM_ALG, 256, 256);
        Hash hash = new Hash();
        AES aes = new AES("BC", SECURE_RANDOM_ALG, "GCM", "NoPadding", 256, 16);

        mapToCurveSecP256k1 = new MapToCurveSecP256k1(hmac, hash);

        cryptoPrimitives = CryptoPrimitives.builder()
                .mapToCurveSecP256k1(mapToCurveSecP256k1)
                //.elGamal()
                .ecElGamal(new ECElGamal())
                .standardCryptos(new StandardCryptos(aes, hash, hmac, new Random(SECURE_RANDOM_ALG)))
                .build();

        coPRF = CoPRF.builder()
                .main(MainImpl.builder().cryptoPrimitives(cryptoPrimitives).build())
                .eval(EvalImpl.builder().cryptoPrimitives(cryptoPrimitives).build())
                .convert(ConvertImpl.builder().cryptoPrimitives(cryptoPrimitives).build())
                .build();
    }
}
