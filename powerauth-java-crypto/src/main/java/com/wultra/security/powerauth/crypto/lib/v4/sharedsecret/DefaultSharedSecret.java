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

package com.wultra.security.powerauth.crypto.lib.v4.sharedsecret;

import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.ByteUtils;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.*;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.KeyFactory;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.DefaultSharedSecretClientContext;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.DefaultSharedSecretRequest;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.DefaultSharedSecretResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.RequestCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.ResponseCryptogram;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

/**
 * Default Shared Secret implementation supporting a list of KEM algorithms used to compute individual
 * shared secrets, concatenating them, and deriving the final shared secret.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class DefaultSharedSecret implements SharedSecret<DefaultSharedSecretRequest, DefaultSharedSecretResponse, DefaultSharedSecretClientContext> {

    private static final String VERSION = "4.0";
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    private final SharedSecretAlgorithm algorithm;
    private final List<Kem> kemAlgorithms;
    private final byte[] diversifier;

    /**
     * Construct a default shared secret implementation.
     * @param algorithm Algorithm descriptor.
     * @param kemAlgorithms List of KEM implementations.
     */
    public DefaultSharedSecret(SharedSecretAlgorithm algorithm, List<Kem> kemAlgorithms) {
        this.algorithm = algorithm;
        this.kemAlgorithms = Collections.unmodifiableList(kemAlgorithms);
        this.diversifier = ByteUtils.encodeString(VERSION);
    }

    @Override
    public SharedSecretAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public RequestCryptogram generateRequestCryptogram() throws GenericCryptoException {
        final List<String> encapsulationKeys = new ArrayList<>();
        final List<PrivateKey> decapsulationKeys = new ArrayList<>();

        try {
            for (Kem kem: kemAlgorithms) {
                final KeyPair keyPair = kem.generateKeyPair();
                decapsulationKeys.add(keyPair.getPrivate());
                final byte[] publicBytes = kem.convertPublicKeyToBytes(keyPair.getPublic());
                encapsulationKeys.add(Base64.getEncoder().encodeToString(publicBytes));
            }
            final DefaultSharedSecretRequest request = new DefaultSharedSecretRequest(
                    algorithm,
                    encapsulationKeys
            );
            final DefaultSharedSecretClientContext context = new DefaultSharedSecretClientContext(decapsulationKeys);
            return new RequestCryptogram(request, context);
        } catch (Exception e) {
            throw new GenericCryptoException("Failed to generate request cryptogram", e);
        }
    }

    @Override
    public ResponseCryptogram generateResponseCryptogram(DefaultSharedSecretRequest request) throws GenericCryptoException {
        if (request == null || request.getAlgorithm() == null || request.getEncapsulationKeys() == null) {
            throw new GenericCryptoException("Invalid shared secret request");
        }
        if (!request.getAlgorithm().equals(algorithm)) {
            throw new GenericCryptoException("Unexpected algorithm: " + request.getAlgorithm());
        }
        List<String> encapsulationKeys = request.getEncapsulationKeys();
        if (encapsulationKeys.size() != kemAlgorithms.size()) {
            throw new GenericCryptoException("Unexpected count of encapsulation keys");
        }

        final List<SecretKey> secretKeys = new ArrayList<>();
        final List<String> encapsulatedKeys = new ArrayList<>();

        try {
            for (int i = 0; i < kemAlgorithms.size(); i++) {
                final Kem kem = kemAlgorithms.get(i);
                final byte[] publicBytes = Base64.getDecoder().decode(encapsulationKeys.get(i));
                final PublicKey publicKey = kem.convertBytesToPublicKey(publicBytes);

                final SecretKeyWithEncapsulation secretWithEncaps = kem.encapsulate(publicKey);
                final SecretKey secret = KEY_CONVERTOR.convertBytesToSharedSecretKey(secretWithEncaps.getEncoded());
                final byte[] encapsulated = secretWithEncaps.getEncapsulation();

                secretKeys.add(secret);
                encapsulatedKeys.add(Base64.getEncoder().encodeToString(encapsulated));
            }

            final byte[] concatenatedBytes = ByteUtils.concat(
                    secretKeys.stream()
                            .map(KEY_CONVERTOR::convertSharedSecretKeyToBytes)
                            .toArray(byte[][]::new)
            );

            final SecretKey concatenatedKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(concatenatedBytes);
            final SecretKey derived = KeyFactory.deriveKeySharedSecret(algorithm, concatenatedKey, diversifier);

            final DefaultSharedSecretResponse response = new DefaultSharedSecretResponse(encapsulatedKeys);
            return new ResponseCryptogram(response, derived);
        } catch (Exception e) {
            throw new GenericCryptoException("Failed to generate response cryptogram", e);
        }
    }

    @Override
    public SecretKey computeSharedSecret(DefaultSharedSecretClientContext context, DefaultSharedSecretResponse response) throws GenericCryptoException {
        if (context == null || response == null || context.getDecapsulationKeys() == null || response.getEncapsulatedKeys() == null) {
            throw new GenericCryptoException("Invalid shared secret response");
        }

        final List<PrivateKey> decapKeys = context.getDecapsulationKeys();
        final List<String> encapsulatedKeys = response.getEncapsulatedKeys();

        if (decapKeys.size() != kemAlgorithms.size() || encapsulatedKeys.size() != kemAlgorithms.size()) {
            throw new GenericCryptoException("Invalid parameter count for decapsulation");
        }

        try {
            final List<SecretKey> secretKeys = new ArrayList<>();
            for (int i = 0; i < kemAlgorithms.size(); i++) {
                final Kem kem = kemAlgorithms.get(i);
                final PrivateKey privateKey = decapKeys.get(i);
                final byte[] ciphertext = Base64.getDecoder().decode(encapsulatedKeys.get(i));
                final SecretKey secret = kem.decapsulate(privateKey, ciphertext);
                secretKeys.add(secret);
            }

            final byte[] concatenatedBytes = ByteUtils.concat(
                    secretKeys.stream()
                            .map(KEY_CONVERTOR::convertSharedSecretKeyToBytes)
                            .toArray(byte[][]::new)
            );

            final SecretKey concatenatedKey = KEY_CONVERTOR.convertBytesToSharedSecretKey(concatenatedBytes);
            return KeyFactory.deriveKeySharedSecret(algorithm, concatenatedKey, diversifier);
        } catch (Exception e) {
            throw new GenericCryptoException("Failed to compute shared secret", e);
        }
    }

}
