/*
 * PowerAuth Crypto Library
 * Copyright 2018 Wultra s.r.o.
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

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesScope;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.ByteUtils;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.crypto.lib.util.Hash;

import java.nio.ByteBuffer;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * Factory for obtaining initialized ECIES encryptor and decryptor instances.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class EciesFactory {

    private final HMACHashUtilities hmacHashUtilities = new HMACHashUtilities();

    /**
     * Get ECIES encryptor instance for application scope.
     *
     * @param publicKey Public key used for ECIES.
     * @param applicationSecret Application secret.
     * @param sharedInfo1 Additional information for sharedInfo1 parameter using pre-defined constants.
     * @param eciesParameters ECIES parameters for protocol V3.2+.
     * @return Initialized ECIES encryptor.
     * @throws GenericCryptoException In case encryptor could not be initialized.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws EciesException In case envelope key could not be derived.
     */
    public EciesEncryptor getEciesEncryptorForApplication(final ECPublicKey publicKey, final byte[] applicationSecret, final EciesSharedInfo1 sharedInfo1,
                                                          final EciesParameters eciesParameters) throws GenericCryptoException, CryptoProviderException, EciesException {
        byte[] sharedInfo1Value = sharedInfo1 == null ? EciesSharedInfo1.APPLICATION_SCOPE_GENERIC.value() : sharedInfo1.value();
        return getEciesEncryptor(EciesScope.APPLICATION_SCOPE, publicKey, applicationSecret, null, sharedInfo1Value, eciesParameters);
    }

    /**
     * Get ECIES encryptor instance for activation scope.
     *
     * @param publicKey Public key used for ECIES.
     * @param applicationSecret Application secret.
     * @param transportKey Transport key.
     * @param sharedInfo1 Additional information for sharedInfo1 parameter using pre-defined constants.
     * @param eciesParameters ECIES parameters for protocol V3.2+.
     * @return Initialized ECIES encryptor.
     * @throws GenericCryptoException In case encryptor could not be initialized.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws EciesException In case envelope key could not be derived.
     */
    public EciesEncryptor getEciesEncryptorForActivation(final ECPublicKey publicKey, final byte[] applicationSecret, final byte[] transportKey,
                                                         final EciesSharedInfo1 sharedInfo1, final EciesParameters eciesParameters) throws GenericCryptoException, CryptoProviderException, EciesException {
        byte[] sharedInfo1Value = sharedInfo1 == null ? EciesSharedInfo1.ACTIVATION_SCOPE_GENERIC.value() : sharedInfo1.value();
        return getEciesEncryptor(EciesScope.ACTIVATION_SCOPE, publicKey, applicationSecret, transportKey, sharedInfo1Value, eciesParameters);
    }

    /**
     * Get ECIES encryptor for existing envelope key and sharedInfo2 parameter.
     *
     * @param envelopeKey ECIES envelope key.
     * @param sharedInfo2 Parameter sharedInfo2 for ECIES.
     * @return Initialized ECIES encryptor.
     */
    public EciesEncryptor getEciesEncryptor(final EciesEnvelopeKey envelopeKey, final byte[] sharedInfo2) {
        return new EciesEncryptor(envelopeKey, sharedInfo2);
    }

    /**
     * Get ECIES encryptor for existing envelope key and ECIES parameters.
     *
     * @param eciesScope ECIES scope.
     * @param envelopeKey ECIES envelope key.
     * @param applicationSecret Application secret.
     * @param transportKey Transport key.
     * @param eciesParameters ECIES parameters for protocol V3.2+.
     * @return Initialized ECIES encryptor.
     * @throws GenericCryptoException In case encryptor could not be initialized.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public EciesEncryptor getEciesEncryptor(final EciesScope eciesScope, final EciesEnvelopeKey envelopeKey,
                                            final byte[] applicationSecret, final byte[] transportKey,
                                            final EciesParameters eciesParameters) throws GenericCryptoException, CryptoProviderException {
        final byte[] sharedInfo2 = generateSharedInfo2(eciesScope, applicationSecret, transportKey, eciesParameters, envelopeKey.getEphemeralKeyPublic());
        return new EciesEncryptor(envelopeKey, sharedInfo2);
    }

    /**
     * Get ECIES encryptor instance for given scope and parameters. Parameter sharedInfo2 is derived based on ECIES scope.
     *
     * @param eciesScope ECIES scope.
     * @param publicKey Public key used for ECIES.
     * @param applicationSecret Application secret.
     * @param transportKey Transport key for activation scope. Use null value for application scope.
     * @param sharedInfo1 Additional information for sharedInfo1 parameter in bytes.
     * @return Initialized ECIES encryptor.
     * @throws GenericCryptoException In case encryptor could not be initialized.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    private EciesEncryptor getEciesEncryptor(final EciesScope eciesScope, final ECPublicKey publicKey, final byte[] applicationSecret,
                                             final byte[] transportKey, final byte[] sharedInfo1,
                                             final EciesParameters eciesParameters) throws GenericCryptoException, CryptoProviderException, EciesException {
        final EciesEnvelopeKey envelopeKey = EciesEnvelopeKey.fromPublicKey(publicKey, sharedInfo1);
        final byte[] sharedInfo2 = generateSharedInfo2(eciesScope, applicationSecret, transportKey, eciesParameters, envelopeKey.getEphemeralKeyPublic());
        return new EciesEncryptor(envelopeKey, sharedInfo2);
    }

    /**
     * Get ECIES decryptor instance for application scope.
     *
     * @param privateKey Private key used for ECIES.
     * @param applicationSecret Application secret.
     * @param sharedInfo1 Additional information for sharedInfo1 parameter using pre-defined constants.
     * @param eciesParameters ECIES parameters for protocol V3.2+.
     * @param ephemeralPublicKey Ephemeral public key.
     * @return Initialized ECIES decryptor.
     * @throws GenericCryptoException In case decryptor could not be initialized.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws EciesException In case envelop key could not be derived.
     */
    public EciesDecryptor getEciesDecryptorForApplication(final ECPrivateKey privateKey, final byte[] applicationSecret, final EciesSharedInfo1 sharedInfo1,
                                                          final EciesParameters eciesParameters, final byte[] ephemeralPublicKey) throws GenericCryptoException, CryptoProviderException, EciesException {
        byte[] sharedInfo1Value = sharedInfo1 == null ? EciesSharedInfo1.APPLICATION_SCOPE_GENERIC.value() : sharedInfo1.value();
        return getEciesDecryptor(EciesScope.APPLICATION_SCOPE, privateKey, applicationSecret, null, sharedInfo1Value, eciesParameters, ephemeralPublicKey);    }

    /**
     * Get ECIES decryptor instance for activation scope.
     *
     * @param privateKey Private key used for ECIES.
     * @param applicationSecret Application secret.
     * @param transportKey Transport key.
     * @param sharedInfo1 Additional information for sharedInfo1 parameter using pre-defined constants.
     * @param eciesParameters ECIES parameters for protocol V3.2+.
     * @param ephemeralPublicKey Ephemeral public key.
     * @return Initialized ECIES decryptor.
     * @throws GenericCryptoException In case decryptor could not be initialized.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public EciesDecryptor getEciesDecryptorForActivation(final ECPrivateKey privateKey, final byte[] applicationSecret, final byte[] transportKey, final EciesSharedInfo1 sharedInfo1,
                                                         final EciesParameters eciesParameters, final byte[] ephemeralPublicKey) throws GenericCryptoException, CryptoProviderException {
        byte[] sharedInfo1Value = sharedInfo1 == null ? EciesSharedInfo1.ACTIVATION_SCOPE_GENERIC.value() : sharedInfo1.value();
        return getEciesDecryptor(EciesScope.ACTIVATION_SCOPE, privateKey, applicationSecret, transportKey, sharedInfo1Value, eciesParameters, ephemeralPublicKey);
    }

    /**
     * Get ECIES decryptor for existing envelope key and sharedInfo2 parameter.
     *
     * @param envelopeKey ECIES envelope key.
     * @param sharedInfo2 Parameter sharedInfo2 for ECIES.
     * @return Initialized ECIES decryptor.
     */
    public EciesDecryptor getEciesDecryptor(final EciesEnvelopeKey envelopeKey, final byte[] sharedInfo2) {
        return new EciesDecryptor(envelopeKey, sharedInfo2);
    }

    /**
     * Get ECIES decrypto for existing envelope key and ECIES parameters.
     *
     * @param eciesScope ECIES scope.
     * @param envelopeKey ECIES envelope key.
     * @param applicationSecret Application secret.
     * @param transportKey Transport key.
     * @param eciesParameters ECIES parameters for protocol V3.2+.
     * @param ephemeralPublicKey Ephemeral public key.
     * @return Initialized ECIES encryptor.
     * @throws GenericCryptoException In case encryptor could not be initialized.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public EciesDecryptor getEciesDecryptor(final EciesScope eciesScope, final EciesEnvelopeKey envelopeKey,
                                            final byte[] applicationSecret, final byte[] transportKey,
                                            final EciesParameters eciesParameters, final byte[] ephemeralPublicKey) throws GenericCryptoException, CryptoProviderException {
        final byte[] sharedInfo2 = generateSharedInfo2(eciesScope, applicationSecret, transportKey, eciesParameters, ephemeralPublicKey);
        return new EciesDecryptor(envelopeKey, sharedInfo2);
    }

    /**
     * Get ECIES decryptor instance for given scope and parameters. Parameter sharedInfo2 is derived based on ECIES scope.
     *
     * @param eciesScope ECIES scope.
     * @param privateKey Private key used for ECIES.
     * @param applicationSecret Application secret.
     * @param transportKey Transport key for activation scope. Use null value for application scope.
     * @param sharedInfo1 Additional information for sharedInfo1 parameter in bytes.
     * @return Initialized ECIES decryptor.
     * @throws GenericCryptoException In case decryptor could not be initialized.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    private EciesDecryptor getEciesDecryptor(final EciesScope eciesScope, final ECPrivateKey privateKey, final byte[] applicationSecret,
                                             final byte[] transportKey, final byte[] sharedInfo1, final EciesParameters eciesParameters,
                                             final byte[] ephemeralPublickey) throws GenericCryptoException, CryptoProviderException {

        final byte[] sharedInfo2 = generateSharedInfo2(eciesScope, applicationSecret, transportKey, eciesParameters, ephemeralPublickey);
        return new EciesDecryptor(privateKey, sharedInfo1, sharedInfo2);
    }

    /**
     * Generate SharedInfo2 parameter for ECIES.
     * @param eciesScope ECIES scope.
     * @param applicationSecret Application secret.
     * @param transportKey Transport key.
     * @param eciesParameters ECIES parameters for protocol V3.2+.
     * @param ephemeralPublicKey Ephemeral public key.
     * @return SharedInfo2 parameter for ECIES.
     * @throws GenericCryptoException In case of invalid ECIES scope.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    private byte[] generateSharedInfo2(final EciesScope eciesScope, final byte[] applicationSecret, final byte[] transportKey,
                                       final EciesParameters eciesParameters, final byte[] ephemeralPublicKey) throws GenericCryptoException, CryptoProviderException {
        byte[] sharedInfo2;
        switch (eciesScope) {
            case APPLICATION_SCOPE -> {
                // Compute hash from APP_SECRET as sharedInfo2
                sharedInfo2 = Hash.sha256(applicationSecret);
            }
            case ACTIVATION_SCOPE -> {
                // The sharedInfo2 is defined as HMAC_SHA256(key: KEY_TRANSPORT, data: APP_SECRET)
                sharedInfo2 = hmacHashUtilities.hash(transportKey, applicationSecret);
            }
            default -> throw new GenericCryptoException("Unsupported ECIES scope: " + eciesScope);
        }
        // For protocol V3.2+, append additional ECIES parameters
        // ByteUtils.concatWithSizes(SH2, NONCE, TIMESTAMP_BYTES, KEY_EPH_PUB, ASSOCIATED_DATA)
        if (eciesParameters != null && eciesParameters.getTimestamp() != null) {
            sharedInfo2 = ByteUtils.concatWithSizes(
                    sharedInfo2,
                    eciesParameters.getNonce(),
                    ByteBuffer.allocate(Long.BYTES).putLong(eciesParameters.getTimestamp()).array(),
                    ephemeralPublicKey,
                    eciesParameters.getAssociatedData());
        }
        return sharedInfo2;
    }
}
