/*
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
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.SharedInfo1Constants;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.crypto.lib.util.Hash;

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
     * @return Initialized ECIES encryptor.
     */
    public EciesEncryptor getEciesEnryptorForApplication(ECPublicKey publicKey, byte[] applicationSecret) {
        return getEciesEnryptor(EciesScope.APPLICATION_SCOPE, publicKey, applicationSecret, null, null);
    }


    /**
     * Get ECIES encryptor instance for activation scope.
     *
     * @param publicKey Public key used for ECIES.
     * @param applicationSecret Application secret.
     * @param transportKey Transport key.
     * @param sharedInfo1 Optional sharedInfo1 parameter.
     * @return Initialized ECIES encryptor.
     */
    public EciesEncryptor getEciesEnryptorForActivation(ECPublicKey publicKey, byte[] applicationSecret, byte[] transportKey, SharedInfo1Constants sharedInfo1) {
        byte[] sharedInfo1Value = sharedInfo1 == null ? null : sharedInfo1.value();
        return getEciesEnryptor(EciesScope.ACTIVATION_SCOPE, publicKey, applicationSecret, transportKey, sharedInfo1Value);
    }

    /**
     * Get ECIES encryptor instance for given scope and parameters. Parameter sharedInfo2 is derived based on ECIES scope.
     *
     * @param eciesScope ECIES scope.
     * @param publicKey Public key used for ECIES.
     * @param applicationSecret Application secret.
     * @param transportKey Transport key.
     * @param sharedInfo1 Optional sharedInfo1 parameter.
     * @return Initialized ECIES encryptor.
     */
    private EciesEncryptor getEciesEnryptor(EciesScope eciesScope, ECPublicKey publicKey, byte[] applicationSecret, byte[] transportKey, byte[] sharedInfo1) {
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
                throw new IllegalStateException("Unsupported ECIES scope: "+eciesScope);
        }
    }

    /**
     * Get ECIES encryptor instance for application scope.
     *
     * @param privateKey Private key used for ECIES.
     * @param applicationSecret Application secret.
     * @return Initialized ECIES decryptor.
     */
    public EciesDecryptor getEciesDecryptorForApplication(ECPrivateKey privateKey, byte[] applicationSecret) {
        return getEciesDecryptor(EciesScope.APPLICATION_SCOPE, privateKey, applicationSecret, null, null);
    }


    /**
     * Get ECIES encryptor instance for activation scope.
     *
     * @param privateKey Private key used for ECIES.
     * @param applicationSecret Application secret.
     * @param transportKey Transport key for activation scope. Use null value for application scope.
     * @param sharedInfo1 Pre-defined sharedInfo1 parameter.
     * @return Initialized ECIES decryptor.
     */
    public EciesDecryptor getEciesDecryptorForActivation(ECPrivateKey privateKey, byte[] applicationSecret, byte[] transportKey, SharedInfo1Constants sharedInfo1) {
        byte[] sharedInfo1Value = sharedInfo1 == null ? null : sharedInfo1.value();
        return getEciesDecryptor(EciesScope.ACTIVATION_SCOPE, privateKey, applicationSecret, transportKey, sharedInfo1Value);
    }

    /**
     * Get ECIES encryptor instance for given scope and parameters. Parameter sharedInfo2 is derived based on ECIES scope.
     *
     * @param eciesScope ECIES scope.
     * @param privateKey Private key used for ECIES.
     * @param applicationSecret Application secret.
     * @param transportKey Transport key for activation scope. Use null value for application scope.
     * @param sharedInfo1 Optional additional information for sharedInfo1 parameter.
     * @return Initialized ECIES decryptor.
     */
    private EciesDecryptor getEciesDecryptor(EciesScope eciesScope, ECPrivateKey privateKey, byte[] applicationSecret, byte[] transportKey, byte[] sharedInfo1) {
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
                throw new IllegalStateException("Unsupported ECIES scope: "+eciesScope);
        }
    }


}
