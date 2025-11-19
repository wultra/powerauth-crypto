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

import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.ByteUtils;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.api.*;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.Kmac;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.DefaultSharedSecretClientContext;
import com.wultra.security.powerauth.crypto.lib.v4.model.context.SharedSecretAlgorithm;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.DefaultSharedSecretRequest;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.DefaultSharedSecretResponse;
import com.wultra.security.powerauth.crypto.lib.v4.model.request.RequestCryptogram;
import com.wultra.security.powerauth.crypto.lib.v4.model.response.ResponseCryptogram;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
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
public class DefaultSharedSecret implements SharedSecret {

    private static final byte[] KDF_CUSTOM_BYTES = "KDF".getBytes(StandardCharsets.UTF_8);
    private static final String LABEL_PREFIX_SHARED_SECRET = "shared-secret/";
    private static final String VERSION = "4.0";

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    private final SharedSecretAlgorithm algorithm;
    private final List<Kem> kemAlgorithms;

    /**
     * Construct a default shared secret implementation.
     * @param algorithm Algorithm descriptor.
     * @param kemAlgorithms List of KEM implementations.
     */
    public DefaultSharedSecret(SharedSecretAlgorithm algorithm, List<Kem> kemAlgorithms) {
        this.algorithm = algorithm;
        this.kemAlgorithms = Collections.unmodifiableList(kemAlgorithms);
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
    public ResponseCryptogram generateResponseCryptogram(SharedSecretRequest requestObject) throws GenericCryptoException {
        if (!(requestObject instanceof DefaultSharedSecretRequest request)) {
            throw new GenericCryptoException("Invalid shared secret request instance");
        }
        if (request.getAlgorithm() == null || request.getEncapsulationKeys() == null) {
            throw new GenericCryptoException("Invalid shared secret request");
        }
        if (!request.getAlgorithm().equals(algorithm)) {
            throw new GenericCryptoException("Unexpected algorithm: " + request.getAlgorithm());
        }
        List<String> encapsulationKeys = request.getEncapsulationKeys();
        if (encapsulationKeys.size() != kemAlgorithms.size()) {
            throw new GenericCryptoException("Unexpected count of encapsulation keys");
        }

        final List<byte[]> secretKeys = new ArrayList<>();
        final List<String> encapsulatedKeys = new ArrayList<>();

        try {
            for (int i = 0; i < kemAlgorithms.size(); i++) {
                final Kem kem = kemAlgorithms.get(i);
                final byte[] publicBytes = Base64.getDecoder().decode(encapsulationKeys.get(i));
                final PublicKey publicKey = kem.convertBytesToPublicKey(publicBytes);

                final SecretKeyWithEncapsulation secretWithEncaps = kem.encapsulate(publicKey);
                final byte[] encapsulated = secretWithEncaps.getEncapsulation();

                secretKeys.add(secretWithEncaps.getEncoded());
                encapsulatedKeys.add(Base64.getEncoder().encodeToString(encapsulated));
            }

            final byte[] salt = KEY_GENERATOR.generateRandomBytes(32);
            final String saltEncoded = Base64.getEncoder().encodeToString(salt);
            final SecretKey derived = deriveSharedSecret(secretKeys, salt);

            final DefaultSharedSecretResponse response = new DefaultSharedSecretResponse(saltEncoded, encapsulatedKeys);
            return new ResponseCryptogram(response, derived);
        } catch (Exception e) {
            throw new GenericCryptoException("Failed to generate response cryptogram", e);
        }
    }

    @Override
    public SecretKey computeSharedSecret(SharedSecretClientContext contextObject, SharedSecretResponse responseObject) throws GenericCryptoException {
        if (!(contextObject instanceof DefaultSharedSecretClientContext context)) {
            throw new GenericCryptoException("Invalid shared secret request instance");
        }
        if (!(responseObject instanceof DefaultSharedSecretResponse response)) {
            throw new GenericCryptoException("Invalid shared secret request instance");
        }
        if (context.getDecapsulationKeys() == null || response.getSalt() == null || response.getEncapsulatedKeys() == null) {
            throw new GenericCryptoException("Invalid shared secret response");
        }

        final List<PrivateKey> decapKeys = context.getDecapsulationKeys();
        final List<String> encapsulatedKeys = response.getEncapsulatedKeys();

        if (decapKeys.size() != kemAlgorithms.size() || encapsulatedKeys.size() != kemAlgorithms.size()) {
            throw new GenericCryptoException("Invalid parameter count for decapsulation");
        }

        try {
            final List<byte[]> secretKeys = new ArrayList<>();
            for (int i = 0; i < kemAlgorithms.size(); i++) {
                final Kem kem = kemAlgorithms.get(i);
                final PrivateKey privateKey = decapKeys.get(i);
                final byte[] ciphertext = Base64.getDecoder().decode(encapsulatedKeys.get(i));
                final SecretKey secret = kem.decapsulate(privateKey, ciphertext);
                secretKeys.add(secret.getEncoded());
            }

            final byte[] salt = Base64.getDecoder().decode(response.getSalt());
            return deriveSharedSecret(secretKeys, salt);
        } catch (Exception e) {
            throw new GenericCryptoException("Failed to compute shared secret", e);
        }
    }


    /**
     * Shared secret derivation according to NIST Special Publication 800-56C.
     */
    private SecretKey deriveSharedSecret(List<byte[]> secretKeys, byte[] salt) throws GenericCryptoException {
        if (secretKeys == null || secretKeys.isEmpty()) {
            throw new GenericCryptoException("Missing shared secrets for KDF");
        }
        if (salt == null) {
            throw new GenericCryptoException("Missing salt for KDF");
        }
        if (salt.length != 32) {
            throw new GenericCryptoException("Invalid salt for KDF");
        }
        final byte[][] secretKeyBytes = secretKeys.toArray(byte[][]::new);          // key conversion to byte[][]
        final byte[] concatenatedBytes = ByteUtils.concatWithSizes(secretKeyBytes); // concatenated secrets Z with their sizes
        final String label = LABEL_PREFIX_SHARED_SECRET + algorithm.name();         // label, e.g. shared-secret/EC_P384_ML_L5
        final byte[] fixedInfo = ByteUtils.concatStrings(label, VERSION);           // fixedInfo = label || version
        final byte[] x = ByteUtils.concat(
                ByteUtils.encodeInt(1),                                             // counter
                concatenatedBytes,                                                  // || Z
                fixedInfo                                                           // || fixedInfo
        );
        final byte[] sharedSecret = Kmac.kmac256(                                   // mapped from: H(x) = KMAC(salt, x, H_outputBits, S)
                salt,
                x,
                KDF_CUSTOM_BYTES,
                32
        );
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(sharedSecret);           // return converted secret key
    }

}
