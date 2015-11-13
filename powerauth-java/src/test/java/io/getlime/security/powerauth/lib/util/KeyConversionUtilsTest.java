/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package io.getlime.security.powerauth.lib.util;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author petrdvorak
 */
public class KeyConversionUtilsTest {

    public KeyConversionUtilsTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of convertPublicKey method, of class KeyConversionUtils.
     */
    @Test
    public void testConvertPublicKey() throws InvalidKeySpecException {
        System.out.println("convertPublicKeyToBytes");
        KeyGenerator keyGenerator = new KeyGenerator();
        KeyPair kp = keyGenerator.generateKeyPair();
        KeyConversionUtils instance = new KeyConversionUtils();

        PublicKey publicKey = kp.getPublic();
        byte[] originalBytes = instance.convertPublicKeyToBytes(publicKey);
        String originalBase64 = BaseEncoding.base64().encode(originalBytes);
        byte[] decodedBytes = BaseEncoding.base64().decode(originalBase64);
        PublicKey decodedPublicKey = instance.convertBytesToPublicKey(decodedBytes);
        assertEquals(publicKey, decodedPublicKey);

        PrivateKey privateKey = kp.getPrivate();
        byte[] originalPrivateBytes = instance.convertPrivateKeyToBytes(privateKey);
        String originalPrivateBase64 = BaseEncoding.base64().encode(originalPrivateBytes);
        byte[] decodedPrivateBytes = BaseEncoding.base64().decode(originalPrivateBase64);
        PrivateKey decodedPrivateKey = instance.convertBytesToPrivateKey(decodedPrivateBytes);
        assertEquals(privateKey, decodedPrivateKey);
    }

}
