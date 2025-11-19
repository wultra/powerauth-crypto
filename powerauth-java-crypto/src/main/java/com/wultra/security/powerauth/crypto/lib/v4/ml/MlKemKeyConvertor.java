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
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcKemKeyConvertor;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * ML-KEM implementation of the PQC KEM key convertor.
 *
 * @author Roman Strobl
 */
public class MlKemKeyConvertor implements PqcKemKeyConvertor {

    private static final Logger logger = LoggerFactory.getLogger(MlKemKeyConvertor.class);

    private final String algorithmName;

    /**
     * Constructs convertor for ML-KEM algorithm.
     */
    public MlKemKeyConvertor() {
        this("ML-KEM");
    }

    /**
     * Constructs convertor for a specific PQC KEM algorithm.
     * @param algorithmName Algorithm name (e.g., "ML-KEM")
     */
    public MlKemKeyConvertor(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    @Override
    public byte[] convertPublicKeyToBytes(PublicKey publicKey) throws GenericCryptoException {
        if (publicKey == null) {
            throw new GenericCryptoException("Missing public key");
        }
        if (!publicKey.getClass().getName().equals(BCMLKEMPublicKey.class.getName())) {
            throw new GenericCryptoException("Invalid public key");
        }
        return publicKey.getEncoded();
    }

    @Override
    public byte[] convertPrivateKeyToBytes(PrivateKey privateKey) throws GenericCryptoException {
        if (privateKey == null) {
            throw new GenericCryptoException("Missing private key");
        }
        if (!privateKey.getClass().getName().equals(BCMLKEMPrivateKey.class.getName())) {
            throw new GenericCryptoException("Invalid private key");
        }
        return privateKey.getEncoded();
    }

    @Override
    public PublicKey convertBytesToPublicKey(byte[] publicKeyBytes) throws GenericCryptoException {
        if (publicKeyBytes == null) {
            throw new GenericCryptoException("Missing public key bytes");
        }
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(algorithmName, PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            logger.debug(e.getMessage(), e);
            throw new GenericCryptoException("Public key conversion failed", e);
        }
    }

    @Override
    public PrivateKey convertBytesToPrivateKey(byte[] privateKeyBytes) throws GenericCryptoException {
        if (privateKeyBytes == null) {
            throw new GenericCryptoException("Missing private key bytes");
        }
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(algorithmName, PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            logger.debug(e.getMessage(), e);
            throw new GenericCryptoException("Private key conversion failed", e);
        }
    }

    @Override
    public byte[] convertSharedSecretKeyToBytes(SecretKey sharedSecretKey) throws GenericCryptoException {
        if (sharedSecretKey == null) {
            throw new GenericCryptoException("Missing shared secret key");
        }
        return sharedSecretKey.getEncoded();
    }

    @Override
    public SecretKey convertBytesToSharedSecretKey(byte[] bytesSecretKey) throws GenericCryptoException {
        if (bytesSecretKey == null) {
            throw new GenericCryptoException("Missing shared secret key bytes");
        }
        return new SecretKeySpec(bytesSecretKey, "RAW");
    }
}
