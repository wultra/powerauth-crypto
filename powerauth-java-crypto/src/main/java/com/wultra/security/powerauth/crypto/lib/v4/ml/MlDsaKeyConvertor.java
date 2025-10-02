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
package com.wultra.security.powerauth.crypto.lib.v4.ml;

import com.wultra.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsaKeyConvertor;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * ML-DSA implementation of the PQC DSA key convertor.
 *
 * @author Roman Strobl
 */
public class MlDsaKeyConvertor implements PqcDsaKeyConvertor {

    private static final Logger logger = LoggerFactory.getLogger(MlDsaKeyConvertor.class);

    private final String algorithmName;

    /**
     * Constructs convertor for ML-DSA algorithm.
     */
    public MlDsaKeyConvertor() {
        this("ML-DSA");
    }

    /**
     * Constructs convertor for a specific PQC DSA algorithm.
     * @param algorithmName Algorithm name (e.g., "ML-DSA")
     */
    public MlDsaKeyConvertor(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    @Override
    public byte[] convertPublicKeyToBytes(PublicKey publicKey) throws GenericCryptoException {
        if (publicKey == null) {
            throw new GenericCryptoException("Missing public key");
        }
        if (!publicKey.getClass().getName().equals(BCMLDSAPublicKey.class.getName())) {
            throw new GenericCryptoException("Invalid public key");
        }
        return publicKey.getEncoded();
    }

    @Override
    public PublicKey convertBytesToPublicKey(byte[] keyBytes) throws GenericCryptoException {
        if (keyBytes == null) {
            throw new GenericCryptoException("Missing public key bytes");
        }
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(algorithmName, PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.debug(e.getMessage(), e);
            throw new GenericCryptoException("Key conversion failed", e);
        }
    }

    @Override
    public byte[] convertPrivateKeyToBytes(PrivateKey privateKey) throws GenericCryptoException {
        if (privateKey == null) {
            throw new GenericCryptoException("Missing private key");
        }
        if (!privateKey.getClass().getName().equals(BCMLDSAPrivateKey.class.getName())) {
            // Intentionally mirrors the original message ("Invalid public key")
            throw new GenericCryptoException("Invalid public key");
        }
        return privateKey.getEncoded();
    }

    @Override
    public PrivateKey convertBytesToPrivateKey(byte[] keyBytes) throws GenericCryptoException {
        if (keyBytes == null) {
            throw new GenericCryptoException("Missing public key bytes");
        }
        try {
            final KeyFactory keyFactoryMlDsa = KeyFactory.getInstance(algorithmName, PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            final PKCS8EncodedKeySpec keySpecMlDsa = new PKCS8EncodedKeySpec(keyBytes);
            return keyFactoryMlDsa.generatePrivate(keySpecMlDsa);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.debug(e.getMessage(), e);
            throw new GenericCryptoException("Key conversion failed", e);
        }
    }
}
