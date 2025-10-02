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
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.v4.api.PqcDsa;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;

/**
 * ML-DSA implementation of the post-quantum digital signature algorithm.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class MlDsa implements PqcDsa {

    private static final Logger logger = LoggerFactory.getLogger(MlDsa.class);

    private final MLDSAParameterSpec dsaParameterSpec;

    /**
     * Construct with default parameter spec (ml_dsa_65).
     */
    public MlDsa() {
        this.dsaParameterSpec = MLDSAParameterSpec.ml_dsa_65;
    }

    /**
     * Construct with a specific parameter spec.
     * @param dsaParameterSpec Algorithm parameter spec.
     * @throws GenericCryptoException In case of missing parameter specification.
     */
    public MlDsa(MLDSAParameterSpec dsaParameterSpec) throws GenericCryptoException {
        if (dsaParameterSpec == null) {
            throw new GenericCryptoException("Missing ML-DSA parameter specification");
        }
        this.dsaParameterSpec = dsaParameterSpec;
    }

    @Override
    public KeyPair generateKeyPair() throws CryptoProviderException {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("MLDSA", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            keyPairGenerator.initialize(dsaParameterSpec);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            logger.debug(e.getMessage(), e);
            throw new CryptoProviderException("Error generating key pair", e);
        }
    }

    @Override
    public byte[] sign(PrivateKey privateKey, byte[] message) throws GenericCryptoException {
        if (privateKey == null) {
            throw new GenericCryptoException("Missing private key when signing a message");
        }
        if (message == null) {
            throw new GenericCryptoException("Missing message to sign");
        }
        try {
            final Signature mlDsa = Signature.getInstance("MLDSA", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            mlDsa.initSign(privateKey);
            mlDsa.update(message);
            return mlDsa.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            logger.debug(e.getMessage(), e);
            throw new GenericCryptoException("Error during signature calculation", e);
        }
    }

    @Override
    public boolean verify(PublicKey publicKey, byte[] message, byte[] signature) throws GenericCryptoException {
        if (publicKey == null) {
            throw new GenericCryptoException("Missing public key when verifying a signature");
        }
        if (message == null) {
            throw new GenericCryptoException("Missing message when verifying a signature");
        }
        if (signature == null) {
            throw new GenericCryptoException("Missing signature to verify");
        }
        try {
            final Signature mlDsa = Signature.getInstance("MLDSA", PowerAuthConfiguration.CRYPTO_PROVIDER_NAME);
            mlDsa.initVerify(publicKey);
            mlDsa.update(message);
            return mlDsa.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            logger.debug(e.getMessage(), e);
            throw new GenericCryptoException("Error during signature verification", e);
        }
    }
}
