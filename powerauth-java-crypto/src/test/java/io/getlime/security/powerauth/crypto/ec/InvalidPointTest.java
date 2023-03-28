/*
 * PowerAuth Crypto Library
 * Copyright 2021 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.getlime.security.powerauth.crypto.ec;

import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for validations during public key import.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class InvalidPointTest {

    private final KeyConvertor keyConvertor = new KeyConvertor();

    /**
     * Add BC crypto provider.
     */
    @BeforeAll
    public static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test of validation for point at infinity.
     */
    @Test
    public void testInfinityValidation() {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        assertTrue(ecSpec.getCurve().getInfinity().isValid());
    }

    /**
     * Test of usage of point at infinity as public key.
     */
    @Test
    public void testInfinityAsPublicKey() throws InvalidKeySpecException, CryptoProviderException {
        try {
            keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("AA=="));
        } catch (GenericCryptoException ex) {
            return;
        }
        fail("Infinity allowed as public key");
    }

    /**
     * Test of validation for invalid point compression.
     */
    @Test
    public void testValidationInvalidPoint1() throws InvalidKeySpecException, CryptoProviderException {
        try {
            // Invalid point compression
            keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("ArcL8EPBRJNXVvj0V4w2nPlg7lEKWg+Q6To3OiHw0Tl/"));
        } catch (GenericCryptoException ex) {
            return;
        }
        fail("EC point validation is missing");
    }

    /**
     * Test of validation for invalid encoding.
     */
    @Test
    void testValidationInvalidPoint2() {
        final GenericCryptoException exception = assertThrows(GenericCryptoException.class, () ->
                keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("Pes+/6wnmrjwVa2L9v2wqUDBYMCtq0qvQ7JIZ6+nZe6fsT+vr85+rUPunAIaK3tRAuIkIROUwYEvj/TlcemQ5Q==")),
                "EC point validation is missing");

        assertEquals("Invalid point encoding 0x3d", exception.getMessage());
    }

    /**
     * Test of validation for point with invalid coordinates outside Fp.
     */
    @Test
    public void testValidationInvalidPoint3() throws InvalidKeySpecException, CryptoProviderException {
        try {
            // Invalid point coordinates
            keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("BGjj8wAErlEt1FNJzH8uhpWN2GSd9apNK0tWaDAN+Bukt5EwKZ6l3YzX475apYQdVbzmg0X2mRysqrvTEPRj8b8="));
        } catch (GenericCryptoException ex) {
            return;
        }
        fail("EC point validation is missing");
    }

    /**
     * Test of validation for point with invalid coordinates inside Fp.
     */
    @Test
    public void testValidationInvalidPoint4() throws InvalidKeySpecException, CryptoProviderException {
        try {
            // Invalid point coordinates
            keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("BMa1eFhnJNtFLU6yFeFgcHMt9iPg074ZUKM9D8tX3nuNk7cKwTbbQG8uHItW8NxvPaMYo0WM87eV5Ud9dB3/14Q="));
        } catch (GenericCryptoException ex) {
            return;
        }
        fail("EC point validation is missing");
    }

    /**
     * Test of validation for point from CVE-2018-5383.
     */
    @Test
    public void testValidationInvalidPoint5() throws InvalidKeySpecException, CryptoProviderException {
        try {
            // Invalid point coordinates
            // x: "82794344854243450371984501721340198645022926339504713863786955730156937886079"
            // y: "33552521881581467670836617859178523407344471948513881718969729275859461829010"
            keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("BLcL8EPBRJNXVvj0V4w2nPlg7lEKWg+Q6To3OiHw0Tl/Si4N7VelFWu4LrQxTDf9QVU5Wn5RmIryiczlMbnBcZI="));
        } catch (GenericCryptoException ex) {
            return;
        }
        fail("EC point validation is missing");
    }

    /**
     * Test of validation for point order. The point is correct, however the curve parameters
     * have been altered to simulate an EC curve fault attack.
     */
    @Test
    public void testValidationInvalidOrder() throws InvalidKeySpecException, CryptoProviderException, IllegalAccessException, NoSuchFieldException {
        KeyConvertor keyConvertor = new KeyConvertor();
        SecP256R1Curve p256curve = (SecP256R1Curve) CustomNamedCurves.getByName("secp256r1").getCurve();
        Class<?> parentClass = p256curve.getClass().getSuperclass().getSuperclass();
        Field orderField = parentClass.getDeclaredField("order");
        orderField.setAccessible(true);
        BigInteger orderValid = p256curve.getOrder();
        orderField.set(p256curve, orderValid.add(BigInteger.ONE));
        try {
            keyConvertor.convertBytesToPublicKey(Base64.getDecoder().decode("BJBAcEeM25rL3lo5GIM9J4ygFzkkY3dPe6dKx6x17XNdG1Jy+FlH31rejjCHYVKcLs8lgKjJTKzyxrxMe+kK4KY="));
        } catch (GenericCryptoException ex) {
            // Revert the P-256 curve order change used only for fault attack simulation
            orderField.set(p256curve, orderValid);
            return;
        }
        fail("EC point validation is missing");
    }

}