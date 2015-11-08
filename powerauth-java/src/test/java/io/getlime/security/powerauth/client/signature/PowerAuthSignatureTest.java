package io.getlime.security.powerauth.client.signature;

import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.util.SignatureUtils;
import io.getlime.security.powerauth.server.signature.PowerAuthServerSignature;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class PowerAuthSignatureTest {

    public PowerAuthSignatureTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of signature generation and validation.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testSignatureForData() throws Exception {
        System.out.println("TEST: Data Signatures");

        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());

        // Prepare data
        KeyGenerator keyGenerator = new KeyGenerator();

        KeyPair serverKeyPair = keyGenerator.generateKeyPair();
        PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
        PublicKey serverPublicKey = serverKeyPair.getPublic();

        KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
        PrivateKey devicePrivateKey = deviceKeyPair.getPrivate();
        PublicKey devicePublicKey = deviceKeyPair.getPublic();

        PowerAuthClientSignature clientSignature = new PowerAuthClientSignature();
        PowerAuthServerSignature serverSignature = new PowerAuthServerSignature();

        for (int i = 0; i < 20; i++) {

            for (int ctr = 0; ctr < 100; ctr++) {

                // generate random data
                byte[] data = keyGenerator.generateRandomBytes((int) (Math.random() * 1000));

                // compute data signature
                SecretKey masterClientKey = clientSignature.generateClientMasterSecretKey(devicePrivateKey, serverPublicKey);
                SecretKey signatureClientKey = clientSignature.generateClientSignatureKey(masterClientKey);
                byte[] signature = clientSignature.signatureForData(data, signatureClientKey, new Long(ctr));
                
                // System.out.println("signature client: " + Arrays.toString(signature));

                // validate data signature
                SecretKey masterServerKey = serverSignature.generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
                assertEquals(masterClientKey, masterServerKey);
                
                SecretKey signatureServerKey = serverSignature.generateServerSignatureKey(masterServerKey);
                assertEquals(signatureClientKey, signatureServerKey);
                
                // System.out.println("signature server: " + Arrays.toString(new SignatureUtils().computePowerAuthSignature(data, signatureServerKey, new Long(ctr))));
                
                boolean isSignatureValid = serverSignature.verifySignatureForData(data, signature, signatureServerKey, new Long(ctr));
                assertTrue(isSignatureValid);

            }
        }
    }

}
