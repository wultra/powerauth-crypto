/*
 * PowerAuth Crypto Library
 * Copyright 2025 Wultra s.r.o.
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
package com.wultra.security.powerauth.crypto.lib.util;

import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Key convertor for conversion of ML keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PqcKemKeyConvertor {

    /**
     * Convert public key for ML-KEM into bytes.
     * @param publicKey Public key.
     * @return Converted public key.
     * @throws GenericCryptoException Thrown in case of conversion error.
     */
    public byte[] convertPublicKeyToBytes(PublicKey publicKey) throws GenericCryptoException {
        if (!(publicKey instanceof MLKEMPublicKey)) {
            throw new GenericCryptoException("Invalid public key");
        }
        return publicKey.getEncoded();
    }

    /**
     * Convert private key for ML-KEM into bytes.
     * @param privateKey Private key.
     * @return Converted private key.
     * @throws GenericCryptoException Thrown in case of conversion error.
     */
    public byte[] convertPrivateKeyToBytes(PrivateKey privateKey) throws GenericCryptoException {
        if (!(privateKey instanceof MLKEMPrivateKey)) {
            throw new GenericCryptoException("Invalid private key");
        }
        return privateKey.getEncoded();
    }

    /**
     * Convert bytes into a public key.
     * @param publicKeyBytes Public key bytes.
     * @return Public key.
     * @throws GenericCryptoException Thrown in case of conversion error.
     */
    public PublicKey convertBytesToPublicKey(byte[] publicKeyBytes) throws GenericCryptoException {
        try {
            final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKeyBytes);
            final byte[] encodedPublicKey = publicKeyInfo.getEncoded();
            final KeyFactory keyFactory = KeyFactory.getInstance("ML-KEM", "BC");
            final PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedPublicKey));
            if (!(publicKey instanceof MLKEMPublicKey)) {
                throw new GenericCryptoException("Invalid public key");
            }
            return publicKey;
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new GenericCryptoException("Public key conversion failed", e);
        }
    }

    /**
     * Convert bytes to private key.
     * @param privateKeyBytes Private key bytes.
     * @return Private key.
     * @throws GenericCryptoException Thrown in case of conversion error.
     */
    public PrivateKey convertBytesToPrivateKey(byte[] privateKeyBytes) throws GenericCryptoException {
        try {
            final PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKeyBytes);
            final byte[] encodedPrivateKey = privateKeyInfo.getEncoded();
            final KeyFactory keyFactory = KeyFactory.getInstance("ML-KEM", "BC");
            final PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));
            if (!(privateKey instanceof MLKEMPrivateKey)) {
                throw new GenericCryptoException("Invalid private key");
            }
            return privateKey;
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new GenericCryptoException("Private key conversion failed", e);
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