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

package com.wultra.security.powerauth.crypto.lib.v4.encryptor.aead;

import com.wultra.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorSecrets;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.AeadUtils;
import com.wultra.security.powerauth.crypto.lib.util.ByteUtils;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SideChannelUtils;
import com.wultra.security.powerauth.crypto.lib.v4.Aead;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.exception.AeadException;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.context.AeadSecrets;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Client encryptor for V4 end-to-end encryption scheme based on AEAD.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class ClientAeadEncryptor implements ClientEncryptor<AeadEncryptedRequest, AeadEncryptedResponse> {

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    private final EncryptorId encryptorId;
    private final EncryptorParameters encryptorParameters;
    private final AeadRequestResponseValidator validator;
    private final byte[] associatedData;

    private AeadSecrets encryptorSecrets;
    private byte[] sharedInfo2;
    private byte[] nonce;

    /**
     * Encryptor constructor.
     *
     * @param encryptorId Encryptor identifier.
     * @param parameters Encryptor parameters.
     * @throws AeadException Thrown in case of a cryptography error.
     */
    public ClientAeadEncryptor(EncryptorId encryptorId, EncryptorParameters parameters) throws AeadException {
        this.encryptorId = encryptorId;
        this.encryptorParameters = parameters;
        this.validator = new AeadRequestResponseValidator(parameters.getProtocolVersion());
        this.associatedData = AeadUtils.deriveAssociatedData(
                encryptorId.scope(),
                parameters.getProtocolVersion(),
                parameters.getApplicationKey(),
                parameters.getActivationIdentifier(),
                parameters.getTemporaryKeyId()
        );
    }

    @Override
    public EncryptorParameters getEncryptorParameters() {
        return encryptorParameters;
    }

    @Override
    public EncryptorId getEncryptorId() {
        return encryptorId;
    }

    @Override
    public void configureSecrets(EncryptorSecrets secrets) throws EncryptorException {
        if (!(secrets instanceof AeadSecrets clientSecrets)) {
            throw new EncryptorException("Unsupported EncryptorSecrets object");
        }
        final byte[] sharedInfo2;
        if (clientSecrets.getSharedInfo2() != null) {
            sharedInfo2 = clientSecrets.getSharedInfo2();
        } else {
            sharedInfo2 = AeadUtils.deriveSharedInfo2(
                    encryptorId.scope(),
                    clientSecrets.getApplicationSecret(),
                    clientSecrets.getKeySharedInfo2()
            );
        }
        this.encryptorSecrets = clientSecrets;
        this.sharedInfo2 = sharedInfo2;
    }

    @Override
    public boolean canEncryptRequest() {
        return encryptorSecrets != null && encryptorSecrets.getEnvelopeKey() != null && sharedInfo2 != null;
    }

    @Override
    public AeadEncryptedRequest encryptRequest(byte[] plaintext) throws EncryptorException {
        if (!canEncryptRequest()) {
            throw new EncryptorException("Encryptor is not ready for request encryption");
        }
        final byte[] nonce = generateNonce();
        this.nonce = nonce;
        final long requestTimestamp = generateTimestamp();
        // Prepare key context (KC parameter) for AEAD
        final byte[] keyContext = AeadUtils.deriveKeyContext(
                encryptorParameters.getProtocolVersion(),
                encryptorId.getEciesSharedInfo1(encryptorParameters.getProtocolVersion()),
                nonce);
        // Prepare final associated data (AD parameter) for AEAD with all available information
        final byte[] associatedDataFinal = AeadUtils.deriveAssociateDataFinal(
                encryptorParameters.getProtocolVersion(),
                sharedInfo2,
                nonce,
                requestTimestamp,
                this.associatedData
        );
        final byte[] requestNonce = Arrays.copyOfRange(nonce, 0, 12);
        final SecretKey sharedSecret = KEY_CONVERTOR.convertBytesToSharedSecretKey(encryptorSecrets.getEnvelopeKey());
        try {
            final byte[] encryptedData = Aead.seal(sharedSecret, keyContext, requestNonce, associatedDataFinal, plaintext);
            return new AeadEncryptedRequest(
                    encryptorParameters.getTemporaryKeyId(),
                    Base64.getEncoder().encodeToString(encryptedData),
                    Base64.getEncoder().encodeToString(nonce),
                    requestTimestamp
            );
        } catch (CryptoProviderException | GenericCryptoException | InvalidKeyException e) {
            throw new EncryptorException("Encryption failed", e);
        }
    }

    @Override
    public boolean canDecryptResponse() {
        return encryptorSecrets != null && encryptorSecrets.getEnvelopeKey() != null && sharedInfo2 != null && nonce != null;
    }

    @Override
    public byte[] decryptResponse(AeadEncryptedResponse response) throws EncryptorException {
        if (!canDecryptResponse()) {
            throw new EncryptorException("Encryptor is not ready for response decryption");
        }
        if (!validator.validateEncryptedResponse(response)) {
            throw new EncryptorException("Invalid encrypted response object");
        }
        try {
            final byte[] ciphertext = Base64.getDecoder().decode(response.getEncryptedData());
            final byte[] extractedNonce = Aead.extractNonce(ciphertext);
            final byte[] iv = ByteUtils.subarray(nonce, 12, 12);
            if (!SideChannelUtils.constantTimeAreEqual(extractedNonce, iv)) {
                throw new AeadException("Invalid nonce");
            }
            final long timestamp = response.getTimestamp();
            // Prepare key context (KC parameter) for AEAD
            final byte[] keyContext = AeadUtils.deriveKeyContext(
                    encryptorParameters.getProtocolVersion(),
                    encryptorId.getEciesSharedInfo1(encryptorParameters.getProtocolVersion()),
                    nonce);
            // Prepare final associated data (AD parameter) for AEAD with all available information
            final byte[] associatedDataFinal = AeadUtils.deriveAssociateDataFinal(
                    encryptorParameters.getProtocolVersion(),
                    sharedInfo2,
                    nonce,
                    timestamp,
                    this.associatedData
            );
            final SecretKey sharedSecret = KEY_CONVERTOR.convertBytesToSharedSecretKey(encryptorSecrets.getEnvelopeKey());
            return Aead.open(sharedSecret, keyContext, associatedDataFinal, ciphertext);
        } catch (GenericCryptoException | CryptoProviderException | InvalidKeyException e) {
            throw new EncryptorException("Decryption failed", e);
        }
    }

    /**
     * Generate current unix timestamp in milliseconds.
     * @return Current unix timestamp.
     */
    private long generateTimestamp() {
        return System.currentTimeMillis();
    }

    /**
     * Generate nonce for the request.
     * @return Nonce bytes or null if protocol doesn't use nonce.
     * @throws AeadException In case of random generator is not configured properly.
     */
    private byte[] generateNonce() throws AeadException {
        try {
            byte[] requestNonce;
            byte[] responseNonce;
            do {
                requestNonce = KEY_GENERATOR.generateRandomBytes(12);
                responseNonce = KEY_GENERATOR.generateRandomBytes(12);
            } while (SideChannelUtils.constantTimeAreEqual(requestNonce, responseNonce));
            return ByteUtils.concat(requestNonce, responseNonce);
        } catch (CryptoProviderException e) {
            throw new AeadException("Failed to generate request nonce", e);
        }
    }

}
