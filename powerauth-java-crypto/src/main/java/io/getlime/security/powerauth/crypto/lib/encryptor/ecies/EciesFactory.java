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

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesScope;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesSharedInfo1;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.crypto.lib.util.Hash;
import io.getlime.security.powerauth.provider.exception.CryptoProviderException;

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
     * @return Initialized ECIES encryptor.
     * @throws GenericCryptoException In case encryptor could not be initialized.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public EciesEncryptor getEciesEncryptorForApplication(ECPublicKey publicKey, byte[] applicationSecret, EciesSharedInfo1 sharedInfo1) throws GenericCryptoException, CryptoProviderException {
        byte[] sharedInfo1Value = sharedInfo1 == null ? EciesSharedInfo1.APPLICATION_SCOPE_GENERIC.value() : sharedInfo1.value();
        return getEciesEncryptor(EciesScope.APPLICATION_SCOPE, publicKey, applicationSecret, null, sharedInfo1Value);
    }

    /**
     * Get ECIES encryptor instance for activation scope.
     *
     * @param publicKey Public key used for ECIES.
     * @param applicationSecret Application secret.
     * @param transportKey Transport key.
     * @param sharedInfo1 Additional information for sharedInfo1 parameter using pre-defined constants.
     * @return Initialized ECIES encryptor.
     * @throws GenericCryptoException In case encryptor could not be initialized.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public EciesEncryptor getEciesEncryptorForActivation(ECPublicKey publicKey, byte[] applicationSecret, byte[] transportKey, EciesSharedInfo1 sharedInfo1) throws GenericCryptoException, CryptoProviderException {
        byte[] sharedInfo1Value = sharedInfo1 == null ? EciesSharedInfo1.ACTIVATION_SCOPE_GENERIC.value() : sharedInfo1.value();
        return getEciesEncryptor(EciesScope.ACTIVATION_SCOPE, publicKey, applicationSecret, transportKey, sharedInfo1Value);
    }

    /**
     * Get ECIES encryptor for existing envelope key and sharedInfo2 parameter.
     *
     * @param envelopeKey ECIES envelope key.
     * @param sharedInfo2 Parameter sharedInfo2 for ECIES.
     * @return Initialized ECIES encryptor.
     */
    public EciesEncryptor getEciesEncryptor(EciesEnvelopeKey envelopeKey, byte[] sharedInfo2) {
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
    private EciesEncryptor getEciesEncryptor(EciesScope eciesScope, ECPublicKey publicKey, byte[] applicationSecret, byte[] transportKey, byte[] sharedInfo1) throws GenericCryptoException, CryptoProviderException {
        switch (eciesScope) {

            case APPLICATION_SCOPE: {
                // Compute hash from APP_SECRET as sharedInfo2
                byte[] sharedInfo2 = Hash.sha256(applicationSecret);
                return new EciesEncryptor(publicKey, sharedInfo1, sharedInfo2);
            }

            case ACTIVATION_SCOPE: {
                // The sharedInfo2 is defined as HMAC_SHA256(key: KEY_TRANSPORT, data: APP_SECRET)
                byte[] sharedInfo2 = hmacHashUtilities.hash(transportKey, applicationSecret);
                return new EciesEncryptor(publicKey, sharedInfo1, sharedInfo2);
            }

            default:
                throw new GenericCryptoException("Unsupported ECIES scope: "+eciesScope);
        }
    }

    /**
     * Get ECIES decryptor instance for application scope.
     *
     * @param privateKey Private key used for ECIES.
     * @param applicationSecret Application secret.
     * @param sharedInfo1 Additional information for sharedInfo1 parameter using pre-defined constants.
     * @return Initialized ECIES decryptor.
     * @throws GenericCryptoException In case decryptor could not be initialized.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public EciesDecryptor getEciesDecryptorForApplication(ECPrivateKey privateKey, byte[] applicationSecret, EciesSharedInfo1 sharedInfo1) throws GenericCryptoException, CryptoProviderException {
        byte[] sharedInfo1Value = sharedInfo1 == null ? EciesSharedInfo1.APPLICATION_SCOPE_GENERIC.value() : sharedInfo1.value();
        return getEciesDecryptor(EciesScope.APPLICATION_SCOPE, privateKey, applicationSecret, null, sharedInfo1Value);
    }

    /**
     * Get ECIES decryptor instance for activation scope.
     *
     * @param privateKey Private key used for ECIES.
     * @param applicationSecret Application secret.
     * @param transportKey Transport key.
     * @param sharedInfo1 Additional information for sharedInfo1 parameter using pre-defined constants.
     * @return Initialized ECIES decryptor.
     * @throws GenericCryptoException In case decryptor could not be initialized.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public EciesDecryptor getEciesDecryptorForActivation(ECPrivateKey privateKey, byte[] applicationSecret, byte[] transportKey, EciesSharedInfo1 sharedInfo1) throws GenericCryptoException, CryptoProviderException {
        byte[] sharedInfo1Value = sharedInfo1 == null ? EciesSharedInfo1.ACTIVATION_SCOPE_GENERIC.value() : sharedInfo1.value();
        return getEciesDecryptor(EciesScope.ACTIVATION_SCOPE, privateKey, applicationSecret, transportKey, sharedInfo1Value);
    }

    /**
     * Get ECIES decryptor for existing envelope key and sharedInfo2 parameter.
     *
     * @param envelopeKey ECIES envelope key.
     * @param sharedInfo2 Parameter sharedInfo2 for ECIES.
     * @return Initialized ECIES decryptor.
     */
    public EciesDecryptor getEciesDecryptor(EciesEnvelopeKey envelopeKey, byte[] sharedInfo2) {
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
    private EciesDecryptor getEciesDecryptor(EciesScope eciesScope, ECPrivateKey privateKey, byte[] applicationSecret, byte[] transportKey, byte[] sharedInfo1) throws GenericCryptoException, CryptoProviderException {
        switch (eciesScope) {

            case APPLICATION_SCOPE: {
                // Compute hash from APP_SECRET as sharedInfo2
                byte[] sharedInfo2 = Hash.sha256(applicationSecret);
                return new EciesDecryptor(privateKey, sharedInfo1, sharedInfo2);
            }

            case ACTIVATION_SCOPE: {
                // The sharedInfo2 is defined as HMAC_SHA256(key: KEY_TRANSPORT, data: APP_SECRET)
                byte[] sharedInfo2 = hmacHashUtilities.hash(transportKey, applicationSecret);
                return new EciesDecryptor(privateKey, sharedInfo1, sharedInfo2);
            }

            default:
                throw new GenericCryptoException("Unsupported ECIES scope: "+eciesScope);
        }
    }

}
