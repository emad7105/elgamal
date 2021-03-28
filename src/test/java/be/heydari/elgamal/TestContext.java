package be.heydari.elgamal;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import junit.framework.TestCase;
import org.junit.Ignore;

@Ignore
public class TestContext extends TestCase {

    public final static String SECURE_RANDOM_ALG = "NativePRNG"; // SHA1PRNG
    public final static Gson gson = new GsonBuilder().setPrettyPrinting().create();


    @Override
    public void setUp() throws Exception {
        super.setUp();
    }
}
