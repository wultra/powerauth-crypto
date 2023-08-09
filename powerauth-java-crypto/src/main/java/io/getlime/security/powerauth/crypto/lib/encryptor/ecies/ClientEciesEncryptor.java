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
    private final byte[] associatedData;        // non-null for V3.2+
    private final boolean useNonceForRequest;   // True for V3.1+
    private final boolean useTimestamp;         // True for V3.2+

    // Variables altered after configureKeys() call.
    private ClientEncryptorSecrets encryptorSecrets;
    private byte[] sharedInfo2Base;

    // Variables created in encrypt method
    private EciesEnvelopeKey envelopeKey;
    private byte[] requestNonce;

    /**
     * Construct ECIES encryptor that implements encryption for PowerAuth Clients.
     * @param encryptorId Encryptor identifier.
     * @param parameters Encryptor parameters.
     */
    public ClientEciesEncryptor(EncryptorId encryptorId, EncryptorParameters parameters) {
        this.encryptorId = encryptorId;
        this.encryptorParameters = parameters;
        this.associatedData = EciesUtils.deriveAssociatedData(
                encryptorId.getScope(),
                parameters.getProtocolVersion(),
                parameters.getApplicationKey(),
                parameters.getActivationIdentifier()
        );
        this.useNonceForRequest = "3.1".equals(parameters.getProtocolVersion()) || "3.2".equals(parameters.getProtocolVersion());
        this.useTimestamp = "3.2".equals(parameters.getProtocolVersion());
    }

    @Override
    public EncryptorParameters getParameters() {
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
                    encryptorId.getScope(),
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
                encryptorId.getEciesSharedInfo1()
        );
        // Prepare nonce and timestamp for the request, if required.
        final byte[] requestNonce = generateRequestNonce();
        final Long requestTimestamp = useTimestamp ? EciesUtils.generateTimestamp() : null;
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
        // If everything is OK, then encrypt the data.
        final EciesPayload eciesPayload = eciesEncryptor.encrypt(
                data,
                new EciesParameters(requestNonce, associatedData, requestTimestamp)
        );
        // Keep envelope key and nonce used for the request if protocol require use the same nonce also for the response.
        this.envelopeKey = envelopeKey;
        this.requestNonce = useTimestamp ? null : requestNonce;

        return new EncryptedRequest(
                Base64.getEncoder().encodeToString(eciesPayload.getCryptogram().getEphemeralPublicKey()),
                Base64.getEncoder().encodeToString(eciesPayload.getCryptogram().getEncryptedData()),
                Base64.getEncoder().encodeToString(eciesPayload.getCryptogram().getMac()),
                useNonceForRequest ? Base64.getEncoder().encodeToString(requestNonce) : null,
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

        // Decode and validate response payload
        if (response.getEncryptedData() == null) {
            throw new EciesException("Missing encryptedData in response data");
        }
        if (response.getMac() == null) {
            throw new EciesException("Missing responseMac in response data");
        }
        if (useTimestamp) {
            // 3.2+
            if (response.getNonce() == null) {
                throw new EciesException("Missing nonce in response data");
            }
            if (response.getTimestamp() == null) {
                throw new EciesException("Missing timestamp in response data");
            }
        }

        final byte[] mac = Base64.getDecoder().decode(response.getMac());
        final byte[] encryptedData = Base64.getDecoder().decode(response.getEncryptedData());
        final byte[] responseNonce = useTimestamp ? Base64.getDecoder().decode(response.getNonce()) : requestNonce;
        final Long responseTimestamp = useTimestamp ? response.getTimestamp() : null;

        // Build sharedInfo2 with parameters received from the request.
        final byte[] sharedInfo2 = EciesUtils.deriveSharedInfo2(
                encryptorParameters.getProtocolVersion(),
                sharedInfo2Base,
                envelopeKey.getEphemeralKeyPublic(),
                responseNonce,
                responseTimestamp,
                associatedData
        );
        // Build decryptor object.
        final EciesDecryptor decryptor = new EciesDecryptor(envelopeKey, sharedInfo2);
        // Prepare EciesPayload and try to decrypt data.
        final byte[] plaintext = decryptor.decrypt(new EciesPayload(
                new EciesCryptogram(envelopeKey.getEphemeralKeyPublic(), mac, encryptedData),
                new EciesParameters(responseNonce, associatedData, responseTimestamp)
        ));
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
            return useNonceForRequest ? keyGenerator.generateRandomBytes(16) : null;
        } catch (CryptoProviderException e) {
            throw new EciesException("Failed to generate request nonce", e);
        }
    }

    // Testing

    /**
     * Get ECIES envelope key. The function should be used only for the testing purposes.
     * @return ECIES envelope key or null if such key is not created yet.
     */
    public EciesEnvelopeKey getEnvelopeKey() {
        return envelopeKey;
    }

    /**
     * Get SharedInfo2 base bytes. The function should be used only for the testing purposes.
     * @return SharedInfo2 base bytes or null if not calculated yet.
     */
    public byte[] getSharedInfo2Base() {
        return sharedInfo2Base;
    }
}
