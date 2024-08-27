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

import io.getlime.security.powerauth.crypto.lib.encryptor.ClientEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesPayload;
import io.getlime.security.powerauth.crypto.lib.encryptor.exception.EncryptorException;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.*;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ClientEncryptorSecrets;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.util.EciesUtils;

import java.util.Base64;

/**
 * Class implements ECIES encryption for PowerAuth clients.
 * <p>PowerAuth protocol versions:
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 * </ul>
 */
public class ClientEciesEncryptor implements ClientEncryptor {

    private static final KeyGenerator keyGenerator = new KeyGenerator();

    private final EncryptorId encryptorId;
    private final EncryptorParameters encryptorParameters;
    private final EciesRequestResponseValidator validator;
    private final byte[] associatedData;        // non-null for V3.2+

    // Variables altered after configureKeys() call.
    private ClientEncryptorSecrets encryptorSecrets;

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
     * Construct ECIES encryptor that implements encryption for PowerAuth Clients.
     * @param encryptorId Encryptor identifier.
     * @param parameters Encryptor parameters.
     * @throws EncryptorException In case that protocol is not supported.
     */
    public ClientEciesEncryptor(EncryptorId encryptorId, EncryptorParameters parameters) throws EncryptorException {
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
        if (!(secrets instanceof ClientEncryptorSecrets clientSecrets)) {
            throw new EncryptorException("Unsupported EncryptorSecrets object");
        }
        final byte[] sharedInfo2Base;
        if (clientSecrets.getSharedInfo2Base() != null) {
            sharedInfo2Base = clientSecrets.getSharedInfo2Base();
        } else {
            sharedInfo2Base = EciesUtils.deriveSharedInfo2Base(
                    encryptorId.scope(),
                    clientSecrets.getApplicationSecret(),
                    clientSecrets.getTransportKey()
            );
        }
        this.encryptorSecrets = clientSecrets;
        this.sharedInfo2Base = sharedInfo2Base;
    }

    @Override
    public boolean canEncryptRequest() {
        return encryptorSecrets != null && sharedInfo2Base != null;
    }

    @Override
    public EncryptedRequest encryptRequest(byte[] data) throws EncryptorException {
        if (!canEncryptRequest()) {
            throw new EncryptorException("Encryptor is not ready for request encryption.");
        }
        // Prepare new envelope key. The function internally generate new ephemeral public key.
        final EciesEnvelopeKey envelopeKey = EciesEnvelopeKey.fromPublicKey(
                encryptorSecrets.getServerPublicKey(),
                encryptorId.getEciesSharedInfo1(encryptorParameters.getProtocolVersion())
        );
        // Prepare nonce and timestamp for the request, if required.
        final byte[] requestNonce = generateRequestNonce();
        final Long requestTimestamp = validator.isUseTimestamp() ? EciesUtils.generateTimestamp() : null;
        // Prepare sharedInfo2 with all available information.
        final byte[] sharedInfo2 = EciesUtils.deriveSharedInfo2(
                encryptorParameters.getProtocolVersion(),
                sharedInfo2Base,
                envelopeKey.getEphemeralKeyPublic(),
                requestNonce,
                requestTimestamp,
                associatedData
        );
        // Once we have SharedInfo2 prepared, we can construct an encryptor.
        final EciesEncryptor eciesEncryptor = new EciesEncryptor(envelopeKey, sharedInfo2);
        // Prepare EciesParameters
        final EciesParameters eciesParameters = new EciesParameters(requestNonce, associatedData, requestTimestamp);
        // If everything is OK, then encrypt the data.
        final EciesPayload eciesPayload = eciesEncryptor.encrypt(data,eciesParameters);
        // Keep envelope key and nonce used for the request if protocol require use the same nonce also for the response.
        this.envelopeKey = envelopeKey;
        this.requestNonce = validator.isUseTimestamp() ? null : requestNonce;

        final Base64.Encoder base64Encoder = Base64.getEncoder();
        final EciesCryptogram eciesCryptogram = eciesPayload.getCryptogram();
        if (eciesCryptogram == null) {
            throw new EncryptorException("The cryptogram value is null.");
        }

        return new EncryptedRequest(
                encryptorParameters.getTemporaryKeyId(),
                base64Encoder.encodeToString(eciesCryptogram.getEphemeralPublicKey()),
                base64Encoder.encodeToString(eciesCryptogram.getEncryptedData()),
                base64Encoder.encodeToString(eciesCryptogram.getMac()),
                validator.isUseNonceForRequest() && requestNonce != null ? base64Encoder.encodeToString(requestNonce) : null,
                requestTimestamp
        );
    }

    @Override
    public boolean canDecryptResponse() {
        return this.envelopeKey != null;
    }

    @Override
    public byte[] decryptResponse(EncryptedResponse response) throws EncryptorException {
        if (!canDecryptResponse()) {
            throw new EncryptorException("Encryptor is not ready for response decryption.");
        }

        // Validate and decode response payload
        if (!validator.validateEncryptedResponse(response)) {
            throw new EncryptorException("Invalid encrypted response object");
        }

        final Base64.Decoder base64Decoder = Base64.getDecoder();
        final byte[] mac = base64Decoder.decode(response.getMac());
        final byte[] encryptedData = base64Decoder.decode(response.getEncryptedData());
        final byte[] responseNonce = validator.isUseTimestamp() ? base64Decoder.decode(response.getNonce()) : requestNonce;
        final Long responseTimestamp = validator.isUseTimestamp() ? response.getTimestamp() : null;

        // Build sharedInfo2 with parameters received from the request.
        final byte[] sharedInfo2 = EciesUtils.deriveSharedInfo2(
                encryptorParameters.getProtocolVersion(),
                sharedInfo2Base,
                null,
                responseNonce,
                responseTimestamp,
                associatedData
        );
        // Build decryptor object.
        final EciesDecryptor decryptor = new EciesDecryptor(envelopeKey, sharedInfo2);
        // Prepare EciesPayload
        final EciesCryptogram eciesCryptogram = new EciesCryptogram(envelopeKey.getEphemeralKeyPublic(), mac, encryptedData);
        final EciesParameters eciesParameters = new EciesParameters(responseNonce, associatedData, responseTimestamp);
        final EciesPayload eciesPayload = new EciesPayload(eciesCryptogram, eciesParameters);
        // Try to decrypt data.
        final byte[] plaintext = decryptor.decrypt(eciesPayload);
        // If everything's OK, then reset the state to do not allow decrypt with the same keys again.
        this.envelopeKey = null;
        this.requestNonce = null;
        // Return decrypted data.
        return plaintext;
    }

    /**
     * Generate nonce for the request.
     * @return Nonce bytes or null if protocol doesn't use nonce.
     * @throws EciesException In case of random generator is not configured properly.
     */
    private byte[] generateRequestNonce() throws EciesException {
        try {
            return validator.isUseNonceForRequest() ? keyGenerator.generateRandomBytes(16) : null;
        } catch (CryptoProviderException e) {
            throw new EciesException("Failed to generate request nonce", e);
        }
    }
}
