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

import com.wultra.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorSecrets;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.AeadUtils;
import com.wultra.security.powerauth.crypto.lib.util.ByteUtils;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.util.SideChannelUtils;
import com.wultra.security.powerauth.crypto.lib.v4.Aead;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.exception.AeadException;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.context.AeadSecrets;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.Base64;

/**
 * Server encryptor for V4 end-to-end encryption scheme based on AEAD.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class ServerAeadEncryptor implements ServerEncryptor<AeadEncryptedRequest, AeadEncryptedResponse> {

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    private final EncryptorId encryptorId;
    private final EncryptorParameters encryptorParameters;
    private final AeadRequestResponseValidator validator;
    private final byte[] associatedData;

    private AeadSecrets encryptorSecrets;
    private byte[] sharedInfo2;
    private byte[] nonce;

    /**
     * Server encryptor.
     *
     * @param encryptorId Encryptor identifier.
     * @param parameters Encryptor parameters.
     * @throws AeadException Thrown in case of a cryptography error.
     */
    public ServerAeadEncryptor(EncryptorId encryptorId, EncryptorParameters parameters) throws AeadException {
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
        if (!(secrets instanceof AeadSecrets serverSecrets)) {
            throw new EncryptorException("Unsupported EncryptorSecrets object");
        }
        final byte[] sharedInfo2;
        if (serverSecrets.getSharedInfo2() != null) {
            sharedInfo2 = serverSecrets.getSharedInfo2();
        } else {
            sharedInfo2 = AeadUtils.deriveSharedInfo2(
                    encryptorId.scope(),
                    serverSecrets.getApplicationSecret(),
                    serverSecrets.getKeySharedInfo2()
            );
        }
        this.encryptorSecrets = serverSecrets;
        this.sharedInfo2 = sharedInfo2;
    }

    @Override
    public boolean canDecryptRequest() {
        return encryptorSecrets != null && encryptorSecrets.getEnvelopeKey() != null && sharedInfo2 != null;
    }

    @Override
    public EncryptorSecrets deriveSecretsForExternalEncryptor(AeadEncryptedRequest request) {
        // Copy envelope key and sharedInfo2 from the encryptor
        return new AeadSecrets(encryptorSecrets.getEnvelopeKey(), sharedInfo2);
    }

    @Override
    public byte[] decryptRequest(AeadEncryptedRequest request) throws EncryptorException {
        if (!canDecryptRequest()) {
            throw new EncryptorException("Encryptor is not ready for request decryption");
        }
        if (!validator.validateEncryptedRequest(request)) {
            throw new EncryptorException("Invalid encrypted request object.");
        }
        try {
            final byte[] ciphertext = Base64.getDecoder().decode(request.getEncryptedData());
            final byte[] nonce = Base64.getDecoder().decode(request.getNonce());
            this.nonce = nonce;
            final byte[] extractedNonce = Aead.extractNonce(ciphertext);
            final byte[] iv = ByteUtils.subarray(nonce, 0, 12);
            if (!SideChannelUtils.constantTimeAreEqual(extractedNonce, iv)) {
                throw new AeadException("Invalid nonce");
            }
            final long timestamp = request.getTimestamp();
            // Prepare key context (KC parameter) for AEAD
            final byte[] keyContext = AeadUtils.deriveKeyContext(
                    encryptorParameters.getProtocolVersion(),
                    encryptorId.getSharedInfo1(encryptorParameters.getProtocolVersion()),
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

    @Override
    public boolean canEncryptResponse() {
        return encryptorSecrets != null && encryptorSecrets.getEnvelopeKey() != null && sharedInfo2 != null && nonce != null;
    }

    @Override
    public AeadEncryptedResponse encryptResponse(byte[] plaintext) throws EncryptorException {
        if (!canEncryptResponse()) {
            throw new EncryptorException("Encryptor is not ready for response encryption");
        }
        final byte[] responseNonce = ByteUtils.subarray(nonce, 12, 12);
        final long responseTimestamp = generateTimestamp();
        // Prepare key context (KC parameter) for AEAD
        final byte[] keyContext = AeadUtils.deriveKeyContext(
                encryptorParameters.getProtocolVersion(),
                encryptorId.getSharedInfo1(encryptorParameters.getProtocolVersion()),
                nonce);
        // Prepare final associated data (AD parameter) for AEAD with all available information
        final byte[] associatedDataFinal = AeadUtils.deriveAssociateDataFinal(
                encryptorParameters.getProtocolVersion(),
                sharedInfo2,
                nonce,
                responseTimestamp,
                this.associatedData
        );
        final SecretKey sharedSecret = KEY_CONVERTOR.convertBytesToSharedSecretKey(encryptorSecrets.getEnvelopeKey());
        try {
            final byte[] encryptedData = Aead.seal(sharedSecret, keyContext, responseNonce, associatedDataFinal, plaintext);
            return new AeadEncryptedResponse(
                    Base64.getEncoder().encodeToString(encryptedData),
                    responseTimestamp
            );
        } catch (CryptoProviderException | GenericCryptoException | InvalidKeyException e) {
            throw new EncryptorException("Encryption failed", e);
        }
    }

    /**
     * Generate current unix timestamp in milliseconds.
     * @return Current unix timestamp.
     */
    private long generateTimestamp() {
        return System.currentTimeMillis();
    }

}
