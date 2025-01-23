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

import io.getlime.security.powerauth.crypto.lib.enums.EcCurve;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP384R1Curve;
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
     * Test of validation for point at infinity for curve P-256.
     */
    @Test
    public void testInfinityValidation_P256() {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        assertTrue(ecSpec.getCurve().getInfinity().isValid());
    }

    /**
     * Test of validation for point at infinity for curve P-384.
     */
    @Test
    public void testInfinityValidation_P384() {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp384r1");
        assertTrue(ecSpec.getCurve().getInfinity().isValid());
    }

    /**
     * Test of usage of point at infinity as public key for curve P-256.
     */
    @Test
    public void testInfinityAsPublicKey_P256() {
        final GenericCryptoException exception = assertThrows(GenericCryptoException.class, () ->
            keyConvertor.convertBytesToPublicKey(EcCurve.P256, Base64.getDecoder().decode("AA==")));

        assertEquals("Invalid public key with point equal to the point at infinity", exception.getMessage());
    }

    /**
     * Test of usage of point at infinity as public key for curve P-384.
     */
    @Test
    public void testInfinityAsPublicKey_P384() {
        final GenericCryptoException exception = assertThrows(GenericCryptoException.class, () ->
                keyConvertor.convertBytesToPublicKey(EcCurve.P384, Base64.getDecoder().decode("AA==")));

        assertEquals("Invalid public key with point equal to the point at infinity", exception.getMessage());
    }

    /**
     * Test of validation for invalid point compression for curve P-256.
     */
    @Test
    public void testValidationInvalidPointCompression_P256() {
        final GenericCryptoException exception = assertThrows(GenericCryptoException.class, () ->
            keyConvertor.convertBytesToPublicKey(EcCurve.P256, Base64.getDecoder().decode("ArcL8EPBRJNXVvj0V4w2nPlg7lEKWg+Q6To3OiHw0Tl/")));

        assertEquals("Invalid point compression", exception.getMessage());
    }

    /**
     * Test of validation for invalid point compression for curve P-384.
     */
    @Test
    public void testValidationInvalidPointCompression_P384() {
        final GenericCryptoException exception = assertThrows(GenericCryptoException.class, () ->
                keyConvertor.convertBytesToPublicKey(EcCurve.P384, Base64.getDecoder().decode("AgD//////////////////////////////////////////v////8AAAAAAAAAAQAAAAA=")));

        assertEquals("Incorrect length for compressed encoding", exception.getMessage());
    }

    /**
     * Test of validation for invalid encoding for curve P-256.
     */
    @Test
    void testValidationInvalidPointEncoding_P256() {
        final GenericCryptoException exception = assertThrows(GenericCryptoException.class, () ->
                keyConvertor.convertBytesToPublicKey(EcCurve.P256, Base64.getDecoder().decode("Pes+/6wnmrjwVa2L9v2wqUDBYMCtq0qvQ7JIZ6+nZe6fsT+vr85+rUPunAIaK3tRAuIkIROUwYEvj/TlcemQ5Q==")));

        assertEquals("Invalid point encoding 0x3d", exception.getMessage());
    }

    /**
     * Test of validation for invalid encoding for curve P-384.
     */
    @Test
    void testValidationInvalidPointEncoding_P384() {
        final GenericCryptoException exception = assertThrows(GenericCryptoException.class, () ->
                        keyConvertor.convertBytesToPublicKey(EcCurve.P384, Base64.getDecoder().decode("Pes+/6wnmrjwVa2L9v2wqUDBYMCtq0qvQ7JIZ6+nZe6fsT+vr85+rUPunAIaK3tRAuIkIROUwYEvj/TlcemQ5Q==")));

        assertEquals("Invalid point encoding 0x3d", exception.getMessage());
    }

    /**
     * Test of validation for point with invalid coordinates outside Fp for curve P-256.
     */
    @Test
    public void testValidationInvalidPointCoordinatesOutsideFp_P256() {
        final GenericCryptoException exception = assertThrows(GenericCryptoException.class, () ->
            keyConvertor.convertBytesToPublicKey(EcCurve.P256, Base64.getDecoder().decode("BP////8AAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAA/////wAAAAEAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAA=")));

        assertEquals("x value invalid for SecP256R1FieldElement", exception.getMessage());
    }

    /**
     * Test of validation for point with invalid coordinates outside Fp for curve P-384.
     */
    @Test
    public void testValidationInvalidPointCoordinatesOutsideFp_P384() {
        final GenericCryptoException exception = assertThrows(GenericCryptoException.class, () ->
                keyConvertor.convertBytesToPublicKey(EcCurve.P384, Base64.getDecoder().decode("BP/////////////////////////////////////////+/////wAAAAAAAAABAAAAAP/////////////////////////////////////////+/////wAAAAAAAAABAAAAAA==")));

        assertEquals("x value invalid for SecP384R1FieldElement", exception.getMessage());
    }

    /**
     * Test of validation for point with invalid coordinates inside Fp for curve P-256.
     */
    @Test
    public void testValidationInvalidPointCoordinatesInsideFp_P256() {
        final GenericCryptoException exception = assertThrows(GenericCryptoException.class, () ->
            keyConvertor.convertBytesToPublicKey(EcCurve.P256, Base64.getDecoder().decode("BMa1eFhnJNtFLU6yFeFgcHMt9iPg074ZUKM9D8tX3nuNk7cKwTbbQG8uHItW8NxvPaMYo0WM87eV5Ud9dB3/14Q=")));

        assertEquals("Invalid point coordinates", exception.getMessage());
    }

    /**
     * Test of validation for point with invalid coordinates inside Fp for curve P-384.
     */
    @Test
    public void testValidationInvalidCoordinatesInsideFp_P384() {
        final GenericCryptoException exception = assertThrows(GenericCryptoException.class, () ->
                keyConvertor.convertBytesToPublicKey(EcCurve.P384, Base64.getDecoder().decode("BH//////////////////////////////////////////f////4AAAAAAAAAAf////1VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU/////6qqqqqqqqqq/////w==")));

        assertEquals("Invalid point coordinates", exception.getMessage());
    }

    /**
     * Test of validation for point from CVE-2018-5383.
     */
    @Test
    public void testValidationInvalidPoint_CVE_2018_5383() {
        // Invalid point coordinates
        // x: "82794344854243450371984501721340198645022926339504713863786955730156937886079"
        // y: "33552521881581467670836617859178523407344471948513881718969729275859461829010"
        final GenericCryptoException exception = assertThrows(GenericCryptoException.class, () ->
                keyConvertor.convertBytesToPublicKey(EcCurve.P256, Base64.getDecoder().decode("BLcL8EPBRJNXVvj0V4w2nPlg7lEKWg+Q6To3OiHw0Tl/Si4N7VelFWu4LrQxTDf9QVU5Wn5RmIryiczlMbnBcZI=")));

        assertEquals("Invalid point coordinates", exception.getMessage());
    }

    /**
     * Test of validation for point order for curve P-256. The point is correct, however the curve parameters
     * have been altered to simulate an EC curve fault attack.
     */
    @Test
    public void testValidationInvalidOrder_P256() throws IllegalAccessException, NoSuchFieldException {
        KeyConvertor keyConvertor = new KeyConvertor();
        SecP256R1Curve p256curve = (SecP256R1Curve) CustomNamedCurves.getByName("secp256r1").getCurve();
        Class<?> parentClass = p256curve.getClass().getSuperclass().getSuperclass();
        Field orderField = parentClass.getDeclaredField("order");
        orderField.setAccessible(true);
        BigInteger orderValid = p256curve.getOrder();
        orderField.set(p256curve, orderValid.add(BigInteger.ONE));
        final GenericCryptoException exception = assertThrows(GenericCryptoException.class, () ->
            keyConvertor.convertBytesToPublicKey(EcCurve.P256, Base64.getDecoder().decode("BJBAcEeM25rL3lo5GIM9J4ygFzkkY3dPe6dKx6x17XNdG1Jy+FlH31rejjCHYVKcLs8lgKjJTKzyxrxMe+kK4KY=")));

        assertEquals("Point order does not match the order defined in EC curve", exception.getMessage());
        orderField.set(p256curve, orderValid);
    }

    /**
     * Test of validation for point order for curve P-384. The point is correct, however the curve parameters
     * have been altered to simulate an EC curve fault attack.
     */
    @Test
    public void testValidationInvalidOrder_P384() throws IllegalAccessException, NoSuchFieldException {
        KeyConvertor keyConvertor = new KeyConvertor();
        SecP384R1Curve p384curve = (SecP384R1Curve) CustomNamedCurves.getByName("secp384r1").getCurve();
        Class<?> parentClass = p384curve.getClass().getSuperclass().getSuperclass();
        Field orderField = parentClass.getDeclaredField("order");
        orderField.setAccessible(true);
        BigInteger orderValid = p384curve.getOrder();
        orderField.set(p384curve, orderValid.add(BigInteger.ONE));
        final GenericCryptoException exception = assertThrows(GenericCryptoException.class, () ->
                keyConvertor.convertBytesToPublicKey(EcCurve.P384, Base64.getDecoder().decode("BHeMuzGxIpretqc1qXwFOFVgBXhkJkuESepqW6gLIGlgDOqrP9uoNYv7kth9rCICs2/XW+sw/bu51Fhg4+VNrllfyOdXBZKHc8A/UUlL1ST5EUAmjzHerPld5IVn2r6oIg==")));

        assertEquals("Point order does not match the order defined in EC curve", exception.getMessage());
        orderField.set(p384curve, orderValid);
    }

}