/*
 * PowerAuth Crypto Library
 * Copyright 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.provider;

import io.getlime.security.powerauth.provider.exception.CryptoProviderException;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1FieldElement;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Point;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * Crypto provider based on BouncyCastle crypto provider.
 *
 * @author Petr Dvorak
 */
public class CryptoProviderUtilBouncyCastle implements CryptoProviderUtil {

    /**
     * Get the provider name, for example "BC" for Bouncy Castle.
     *
     * @return Name of the provider, for example "BC" for Bouncy Castle.
     */
    @Override
    public String getProviderName() {
        return "BC";
    }

    /**
     * Converts an EC public key to a byte array by encoding Q point parameter.
     *
     * @param publicKey An EC public key to be converted.
     * @return A byte array representation of the EC public key.
     */
    public byte[] convertPublicKeyToBytes(PublicKey publicKey) {
        ClassLoader clBc = Security.getProvider("BC").getClass().getClassLoader();
        if (clBc == getClass().getClassLoader() || clBc == getClass().getClassLoader().getParent()) {
            // BC library was loaded using same classloader as current classloader or its parent
            return ((ECPublicKey) publicKey).getQ().getEncoded(false);
        } else {
            // BC library has its own classloader, reflection needs to be used
            try {
                Object q = publicKey.getClass().getMethod("getQ").invoke(publicKey);
                return (byte[]) q.getClass().getMethod("getEncoded", boolean.class).invoke(q, false);
            } catch (Exception e) {
                return null;
            }
        }
    }

    /**
     * Converts byte array to an EC public key, by decoding the Q point
     * parameter.
     *
     * @param keyBytes Bytes to be converted to EC public key.
     * @return An instance of the EC public key on success, or null on failure.
     * @throws InvalidKeySpecException When provided bytes are not a correct key
     *                                 representation.
     * @throws CryptoProviderException When crypto provider is incorrectly initialized.
     */
    public PublicKey convertBytesToPublicKey(byte[] keyBytes) throws InvalidKeySpecException, CryptoProviderException {
        try {
            KeyFactory kf = KeyFactory.getInstance("ECDH", getProviderName());

            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            if (ecSpec == null) { // can happen with incorrectly initialized crypto provider.
                throw new CryptoProviderException("Crypto provider does not support the secp256r1 curve");
            }
            ECPoint point = ecSpec.getCurve().decodePoint(keyBytes);

            ClassLoader clBc = Security.getProvider("BC").getClass().getClassLoader();
            if (clBc == getClass().getClassLoader() || clBc == getClass().getClassLoader().getParent()) {
                // BC library was loaded using same classloader as current classloader or its parent
                ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
                return kf.generatePublic(pubSpec);
            } else {
                // BC library has its own classloader, it needs to be used
                Object ecSpecBc = getEcKeySpecBc(clBc, ecSpec);
                Object pubSpec = getEcPubKeySpecBc(clBc, ecSpecBc, point);
                return (PublicKey) kf.getClass().getMethod("generatePublic", clBc.loadClass(KeySpec.class.getName())).invoke(kf, pubSpec);
            }

        } catch (NoSuchProviderException | NoSuchAlgorithmException | ClassNotFoundException | IllegalAccessException | InstantiationException | InvocationTargetException | NoSuchMethodException ex) {
            throw new CryptoProviderException(ex.getMessage(), ex);
        }
    }

    /**
     * Converts an EC private key to bytes by encoding the D number parameter.
     *
     * @param privateKey An EC private key to be converted to bytes.
     * @return A byte array containing the representation of the EC private key.
     */
    public byte[] convertPrivateKeyToBytes(PrivateKey privateKey) {
        ClassLoader clBc = Security.getProvider("BC").getClass().getClassLoader();
        if (clBc == getClass().getClassLoader() || clBc == getClass().getClassLoader().getParent()) {
            // BC library was loaded using same classloader as current classloader or its parent
            return ((ECPrivateKey) privateKey).getD().toByteArray();
        } else {
            // BC library has its own classloader, reflection needs to be used
            try {
                Object d = privateKey.getClass().getMethod("getD").invoke(privateKey);
                return (byte[]) d.getClass().getMethod("toByteArray").invoke(d);
            } catch (Exception e) {
                return null;
            }
        }
    }

    /**
     * Convert a byte array to an EC private key by decoding the D number
     * parameter.
     *
     * @param keyBytes Bytes to be converted to the EC private key.
     * @return An instance of EC private key decoded from the input bytes.
     * @throws InvalidKeySpecException The provided key bytes are not a valid EC
     *                                 private key.
     * @throws CryptoProviderException When crypto provider is incorrectly initialized.
     */
    public PrivateKey convertBytesToPrivateKey(byte[] keyBytes) throws InvalidKeySpecException, CryptoProviderException {
        try {
            KeyFactory kf = KeyFactory.getInstance("ECDH", getProviderName());
            BigInteger keyInteger = new BigInteger(keyBytes);
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");

            ClassLoader clBc = Security.getProvider("BC").getClass().getClassLoader();
            if (clBc == getClass().getClassLoader() || clBc == getClass().getClassLoader().getParent()) {
                // BC library was loaded using same classloader as current classloader or its parent
                ECPrivateKeySpec pubSpec = new ECPrivateKeySpec(keyInteger, ecSpec);
                return kf.generatePrivate(pubSpec);
            } else {
                // BC library has its own classloader, it needs to be used
                Object ecSpecBc = getEcKeySpecBc(clBc, ecSpec);
                Object pubSpec = getEcPrivKeySpecBc(clBc, ecSpecBc, keyInteger);
                return (PrivateKey) kf.getClass().getMethod("generatePrivate", clBc.loadClass(KeySpec.class.getName())).invoke(kf, pubSpec);
            }

        } catch (NoSuchAlgorithmException | NoSuchProviderException | ClassNotFoundException | IllegalAccessException | InstantiationException | InvocationTargetException | NoSuchMethodException ex) {
            ex.printStackTrace();
            throw new CryptoProviderException(ex.getMessage(), ex);
        }
    }

    /**
     * Converts a shared secret key (usually used for AES based operations) to a
     * byte array.
     *
     * @param sharedSecretKey A shared key to be converted to bytes.
     * @return A byte array representation of the shared secret key.
     */
    public byte[] convertSharedSecretKeyToBytes(SecretKey sharedSecretKey) {
        return sharedSecretKey.getEncoded();
    }

    /**
     * Converts a byte array to the secret shared key (usually used for AES
     * based operations).
     *
     * @param bytesSecretKey Bytes representing the shared key.
     * @return An instance of the secret key by decoding from provided bytes.
     */
    public SecretKey convertBytesToSharedSecretKey(byte[] bytesSecretKey) {
        return new SecretKeySpec(bytesSecretKey, "AES/ECB/NoPadding");
    }

    /**
     * Get EC key spec loaded using Bouncy Castle provider classloader.
     * @param cl BC classloader.
     * @param ecSpec EC parameter spec.
     * @return EC key spec object.
     * @throws ClassNotFoundException In case of class not found.
     * @throws NoSuchMethodException In case of method not found.
     * @throws IllegalAccessException In case of illegal access.
     * @throws InstantiationException In case of instantiation error.
     * @throws InvocationTargetException In case of invocation error.
     */
    private Object getEcKeySpecBc(ClassLoader cl, ECParameterSpec ecSpec) throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InstantiationException, InvocationTargetException {
        Object x = cl.loadClass(SecP256R1FieldElement.class.getName()).getConstructor(BigInteger.class).newInstance(ecSpec.getG().getAffineXCoord().toBigInteger());
        Object y = cl.loadClass(SecP256R1FieldElement.class.getName()).getConstructor(BigInteger.class).newInstance(ecSpec.getG().getAffineYCoord().toBigInteger());
        Object curve = cl.loadClass(SecP256R1Curve.class.getName()).newInstance();
        Object g = cl.loadClass(SecP256R1Point.class.getName()).getConstructor(cl.loadClass(ECCurve.class.getName()), cl.loadClass(ECFieldElement.class.getName()), cl.loadClass(ECFieldElement.class.getName())).newInstance(curve, x, y);
        return cl.loadClass(ECParameterSpec.class.getName()).getConstructor(cl.loadClass(ECCurve.class.getName()), cl.loadClass(ECPoint.class.getName()), BigInteger.class, BigInteger.class, byte[].class).newInstance(curve, g, ecSpec.getN(), ecSpec.getH(), ecSpec.getSeed());
    }

    /**
     * Get EC public key spec loaded using Bouncy Castle provider classloader.
     * @param cl BC classloader.
     * @param point Public key point.
     * @return EC public key spec object.
     * @throws ClassNotFoundException In case of class not found.
     * @throws NoSuchMethodException In case of method not found.
     * @throws IllegalAccessException In case of illegal access.
     * @throws InstantiationException In case of instantiation error.
     * @throws InvocationTargetException In case of invocation error.
     */
    private Object getEcPubKeySpecBc(ClassLoader cl, Object ecSpec, ECPoint point) throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        Object curve = cl.loadClass(SecP256R1Curve.class.getName()).newInstance();
        Object xPub = cl.loadClass(SecP256R1FieldElement.class.getName()).getConstructor(BigInteger.class).newInstance(point.getAffineXCoord().toBigInteger());
        Object yPub = cl.loadClass(SecP256R1FieldElement.class.getName()).getConstructor(BigInteger.class).newInstance(point.getAffineYCoord().toBigInteger());
        Object pointPub = cl.loadClass(SecP256R1Point.class.getName()).getConstructor(cl.loadClass(ECCurve.class.getName()), cl.loadClass(ECFieldElement.class.getName()), cl.loadClass(ECFieldElement.class.getName())).newInstance(curve, xPub, yPub);
        return cl.loadClass(ECPublicKeySpec.class.getName()).getConstructor(cl.loadClass(ECPoint.class.getName()), cl.loadClass(ECParameterSpec.class.getName())).newInstance(pointPub, ecSpec);
    }

    /**
     * Get EC private key spec loaded using Bouncy Castle provider classloader.
     * @param cl BC classloader.
     * @param ecSpec EC spec.
     * @param keyInteger Public key point as BigInteger.
     * @return EC public key spec object.
     * @throws ClassNotFoundException In case of class not found.
     * @throws NoSuchMethodException In case of method not found.
     * @throws IllegalAccessException In case of illegal access.
     * @throws InstantiationException In case of instantiation error.
     * @throws InvocationTargetException In case of invocation error.
     */
    private Object getEcPrivKeySpecBc(ClassLoader cl, Object ecSpec, BigInteger keyInteger) throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        return cl.loadClass(ECPrivateKeySpec.class.getName()).getConstructor(BigInteger.class, ecSpec.getClass()).newInstance(keyInteger, ecSpec);
    }

}
