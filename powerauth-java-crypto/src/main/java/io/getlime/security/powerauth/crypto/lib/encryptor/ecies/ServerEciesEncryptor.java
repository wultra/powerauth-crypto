/*
 * PowerAuth Crypto Library
 * Copyright 2023 Wultra s.r.o.
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

package io.getlime.security.powerauth.crypto.lib.encryptor.ecies;

import io.getlime.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesPayload;
import io.getlime.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.*;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ServerEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.util.EciesUtils;

import java.util.Arrays;
import java.util.Base64;

/**
 * Class implements ECIES encryption for PowerAuth Server.
 * <p>PowerAuth protocol versions:
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 * </ul>
 */
public class ServerEciesEncryptor implements ServerEncryptor {

    private static final KeyGenerator keyGenerator = new KeyGenerator();

    private final EncryptorId encryptorId;
    private final EncryptorParameters encryptorParameters;
    private final EciesRequestResponseValidator validator;
    private final byte[] associatedData;        // non-null for V3.2+

    // Variables altered after configureKeys() call.

    private ServerEncryptorSecrets encryptorSecrets;

    /**
     * SharedInfo2 base bytes.
     */
    private byte[] sharedInfo2Base;

    // Variables created in encrypt method

    /**
     * ECIES envelope key.
     */
    private EciesEnvelopeKey envelopeKey;
    private byte[] requestNonce;

    /**
     * Construct ECIES encryptor that implements encryption for PowerAuth Server.
     * @param encryptorId Encryptor identifier.
     * @param parameters Encryptor parameters.
     * @throws EncryptorException In case that protocol is not supported.
     */
    public ServerEciesEncryptor(EncryptorId encryptorId, EncryptorParameters parameters) throws EncryptorException {
        this.encryptorId = encryptorId;
        this.encryptorParameters = parameters;
        this.validator = new EciesRequestResponseValidator(parameters.getProtocolVersion());
        this.associatedData = EciesUtils.deriveAssociatedData(
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
        if (!(secrets instanceof ServerEncryptorSecrets serverSecrets)) {
            throw new EncryptorException("Unsupported EncryptorSecrets object");
        }
        final byte[] sharedInfo2Base;
        if (serverSecrets.getSharedInfo2Base() != null) {
            sharedInfo2Base = serverSecrets.getSharedInfo2Base();
        } else {
            sharedInfo2Base = EciesUtils.deriveSharedInfo2Base(
                    encryptorId.scope(),
                    serverSecrets.getApplicationSecret(),
                    serverSecrets.getTransportKey()
            );
        }
        this.encryptorSecrets = serverSecrets;
        this.sharedInfo2Base = sharedInfo2Base;
    }

    @Override
    public boolean canDecryptRequest() {
        return encryptorSecrets != null && sharedInfo2Base != null;
    }

    @Override
    public EncryptorSecrets calculateSecretsForExternalEncryptor(EncryptedRequest request) throws EncryptorException {
        if (!canDecryptRequest()) {
            throw new EncryptorException("Encryptor is not ready for request decryption.");
        }
        if (request.getEphemeralPublicKey() == null) {
            throw new EciesException("Missing ephemeralPublicKey in request data");
        }
        final byte[] ephemeralPublicKey = Base64.getDecoder().decode(request.getEphemeralPublicKey());
        final EciesEnvelopeKey envelopeKey;
        if (encryptorSecrets.getEnvelopeKey() != null) {
            // Envelope key is precalculated. This doesn't happen in V3.2 protocol but may happen in future 4.0.
            envelopeKey = new EciesEnvelopeKey(encryptorSecrets.getEnvelopeKey(), ephemeralPublicKey);
        } else {
            // Derive shared secret from private key and ephemeral public key.
            envelopeKey = EciesEnvelopeKey.fromPrivateKey(
                    encryptorSecrets.getServerPrivateKey(),
                    ephemeralPublicKey,
                    encryptorId.getEciesSharedInfo1(encryptorParameters.getProtocolVersion())
            );
        }
        // Return secrets object with the precalculated keys.
        return new ServerEncryptorSecrets(envelopeKey.getSecretKey(), sharedInfo2Base);
    }

    @Override
    public byte[] decryptRequest(EncryptedRequest request) throws EncryptorException {
        if (!canDecryptRequest()) {
            throw new EncryptorException("Encryptor is not ready for request decryption.");
        }
        // Validate and decode request payload
        if (!validator.validateEncryptedRequest(request)) {
            throw new EncryptorException("Invalid encrypted request object.");
        }

        final byte[] ephemeralPublicKey = Base64.getDecoder().decode(request.getEphemeralPublicKey());
        final byte[] encryptedData = Base64.getDecoder().decode(request.getEncryptedData());
        final byte[] mac = Base64.getDecoder().decode(request.getMac());
        final byte[] requestNonce = request.getNonce() != null ? Base64.getDecoder().decode(request.getNonce()) : null;
        final Long requestTimestamp = request.getTimestamp();

        // Prepare new envelope key, depending on secret's configuration.
        final EciesEnvelopeKey envelopeKey;
        if (encryptorSecrets.getEnvelopeKey() != null) {
            // Envelope key is precalculated
            envelopeKey = new EciesEnvelopeKey(encryptorSecrets.getEnvelopeKey(), ephemeralPublicKey);
        } else {
            // Derive shared secret from private key and ephemeral public key.
            envelopeKey = EciesEnvelopeKey.fromPrivateKey(
                    encryptorSecrets.getServerPrivateKey(),
                    ephemeralPublicKey,
                    encryptorId.getEciesSharedInfo1(encryptorParameters.getProtocolVersion())
            );
        }
        // Prepare sharedInfo2 for all available information.
        final byte[] sharedInfo2 = EciesUtils.deriveSharedInfo2(
                encryptorParameters.getProtocolVersion(),
                sharedInfo2Base,
                ephemeralPublicKey,
                requestNonce,
                requestTimestamp,
                associatedData
        );
        // Once we have SharedInfo2 prepared, we can construct a decryptor.
        final EciesDecryptor eciesDecryptor = new EciesDecryptor(envelopeKey, sharedInfo2);
        // Prepare EciesPayload
        final EciesCryptogram eciesCryptogram = new EciesCryptogram(ephemeralPublicKey, mac, encryptedData);
        final EciesParameters eciesParameters = new EciesParameters(requestNonce, associatedData, requestTimestamp);
        final EciesPayload eciesPayload = new EciesPayload(eciesCryptogram, eciesParameters);
        // Try to decrypt data.
        final byte[] plaintext = eciesDecryptor.decrypt(eciesPayload);
        // Keep envelope key and nonce used for the request if protocol require use the same nonce also for the response.
        this.envelopeKey = envelopeKey;
        this.requestNonce = validator.isUseTimestamp() ? null : requestNonce;
        // Return decrypted data.
        return plaintext;
    }

    @Override
    public boolean canEncryptResponse() {
        return this.envelopeKey != null;
    }

    @Override
    public EncryptedResponse encryptResponse(byte[] data) throws EncryptorException {
        if (!canEncryptResponse()) {
            throw new EncryptorException("Encryptor is not ready for response encryption.");
        }
        // Prepare nonce and timestamp for the response, if required.
        final byte[] responseNonce = getResponseNonce();
        final Long responseTimestamp = validator.isUseTimestamp() ? EciesUtils.generateTimestamp() : null;
        // Prepare SharedInfo2 with all available information.
        final byte[] sharedInfo2 = EciesUtils.deriveSharedInfo2(
                encryptorParameters.getProtocolVersion(),
                sharedInfo2Base,
                null,
                responseNonce,
                responseTimestamp,
                associatedData
        );
        // Once we have SharedInfo2 prepared, we can construct an encryptor.
        final EciesEncryptor eciesEncryptor = new EciesEncryptor(envelopeKey, sharedInfo2);
        // Prepare EciesParameters
        final EciesParameters eciesParameters = new EciesParameters(responseNonce, associatedData, responseTimestamp);
        // If everything is OK, then encrypt data.
        final EciesPayload eciesPayload = eciesEncryptor.encrypt(data, eciesParameters);
        // If everything's OK, then reset the state to do not allow to encrypt with the same keys again.
        this.envelopeKey = null;
        this.requestNonce = null;

        return new EncryptedResponse(
                Base64.getEncoder().encodeToString(eciesPayload.getCryptogram().getEncryptedData()),
                Base64.getEncoder().encodeToString(eciesPayload.getCryptogram().getMac()),
                validator.isUseTimestamp() ? Base64.getEncoder().encodeToString(responseNonce) : null,
                responseTimestamp
        );
    }

    /**
     * Get nonce for the response depending on the protocol version. If protocol require to use unique nonce
     * for the response, then generate new one.
     * @return Nonce bytes or null if protocol doesn't use nonce.
     * @throws EciesException In case of random generator is not configured properly.
     */
    private byte[] getResponseNonce() throws EciesException {
        try {
            if (!validator.isUseTimestamp()) {
                // 3.0 - null
                // 3.1 - the same nonce
                return requestNonce;
            }
            // 3.2+
            for (int attempts = 0; attempts < 8; attempts++) {
                byte[] responseNonce = keyGenerator.generateRandomBytes(16);
                if (!Arrays.equals(responseNonce, requestNonce)) {
                    return responseNonce;
                }
            }
            throw new EciesException("Failed to generate unique response nonce");
        } catch (CryptoProviderException e) {
            throw new EciesException("Failed to generate response nonce", e);
        }
    }
}
