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
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

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
        return ((ECPublicKey) publicKey).getQ().getEncoded(false);
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
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);

            return kf.generatePublic(pubSpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
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
        return ((ECPrivateKey) privateKey).getD().toByteArray();
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
            ECPrivateKeySpec pubSpec = new ECPrivateKeySpec(keyInteger, ecSpec);

            return kf.generatePrivate(pubSpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
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
        return new SecretKeySpec(bytesSecretKey, "AES");
    }

}
