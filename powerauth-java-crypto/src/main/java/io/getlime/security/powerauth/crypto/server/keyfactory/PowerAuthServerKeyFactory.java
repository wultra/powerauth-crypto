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
package io.getlime.security.powerauth.crypto.server.keyfactory;

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthDerivedKey;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;


/**
 * Key factory used on server side to generate PowerAuth related keys.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class PowerAuthServerKeyFactory {

    private final KeyGenerator keyGenerator = new KeyGenerator();

    /**
     * Generate a list with signature keys for given signature type and master secret
     * @param signatureType Requested signature type
     * @param masterSecretKey Master Key Secret
     * @return List with keys constructed from master secret that are needed to get
     * requested signature type.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public List<SecretKey> keysForSignatureType(PowerAuthSignatureTypes signatureType, SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {

        List<SecretKey> signatureKeys = new ArrayList<>();

        if (signatureType == null) {
            return signatureKeys;
        }

        if (signatureType.equals(PowerAuthSignatureTypes.POSSESSION)) {

            SecretKey signatureKey = generateServerSignaturePossessionKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.KNOWLEDGE)) {

            SecretKey signatureKey = generateServerSignatureKnowledgeKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.BIOMETRY)) {

            SecretKey signatureKey = generateServerSignatureBiometryKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE)) {

            SecretKey signatureKey = generateServerSignaturePossessionKey(masterSecretKey);
            signatureKeys.add(signatureKey);
            signatureKey = generateServerSignatureKnowledgeKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.POSSESSION_BIOMETRY)) {

            SecretKey signatureKey = generateServerSignaturePossessionKey(masterSecretKey);
            signatureKeys.add(signatureKey);
            signatureKey = generateServerSignatureBiometryKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        } else if (signatureType.equals(PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY)) {

            SecretKey signatureKey = generateServerSignaturePossessionKey(masterSecretKey);
            signatureKeys.add(signatureKey);
            signatureKey = generateServerSignatureKnowledgeKey(masterSecretKey);
            signatureKeys.add(signatureKey);
            signatureKey = generateServerSignatureBiometryKey(masterSecretKey);
            signatureKeys.add(signatureKey);

        }

        return signatureKeys;

    }

    /**
     * Generate a transport key KEY_ENCRYPTED_VAULT from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_ENCRYPTED_VAULT.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateServerEncryptedVaultKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthDerivedKey.ENCRYPTED_VAULT.getIndex()
        );
    }

    /**
     * Generate a master secret key KEY_MASTER_SECRET using the server private
     * key KEY_SERVER_PRIVATE and device public key KEY_DEVICE_PUBLIC.
     *
     * @param serverPrivateKey Server private key KEY_SERVER_PRIVATE.
     * @param devicePublicKey Device public key KEY_DEVICE_PUBLIC.
     * @return Computed symmetric key KEY_MASTER_SECRET.
     * @throws InvalidKeyException In case some provided key is invalid.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateServerMasterSecretKey(
            PrivateKey serverPrivateKey,
            PublicKey devicePublicKey) throws InvalidKeyException, CryptoProviderException {
        return keyGenerator.computeSharedKey(serverPrivateKey, devicePublicKey);
    }

    /**
     * Generate a signature key KEY_SIGNATURE_BIOMETRY from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_SIGNATURE_BIOMETRY.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateServerSignatureBiometryKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthDerivedKey.SIGNATURE_BIOMETRY.getIndex()
        );
    }

    /**
     * Generate a signature key KEY_SIGNATURE_KNOWLEDGE from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_SIGNATURE_KNOWLEDGE.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateServerSignatureKnowledgeKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthDerivedKey.SIGNATURE_KNOWLEDGE.getIndex()
        );
    }

    /**
     * Generate a signature key KEY_SIGNATURE_POSSESSION from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_SIGNATURE_POSSESSION.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateServerSignaturePossessionKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthDerivedKey.SIGNATURE_POSSESSION.getIndex()
        );
    }

    /**
     * Generate a transport key KEY_TRANSPORT from master secret key
     * KEY_MASTER_SECRET using KDF.
     *
     * @see KeyGenerator#deriveSecretKey(SecretKey, byte[])
     * @param masterSecretKey Master secret key KEY_MASTER_SECRET.
     * @return An instance of signature key KEY_TRANSPORT.
     * @throws InvalidKeyException In case master secret key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey generateServerTransportKey(SecretKey masterSecretKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        return keyGenerator.deriveSecretKey(
                masterSecretKey,
                PowerAuthDerivedKey.TRANSPORT.getIndex()
        );
    }

    /**
     * Derive transport key KEY_TRANSPORT in two steps:
     * 1. Generate KEY_MASTER_SECRET using KEY_SERVER_PRIVATE and KEY_DEVICE_PUBLIC.
     * 2. Generate KEY_TRANSPORT from previously generated KEY_MASTER_SECRET using KDF.
     *
     * @param serverPrivateKey Server private key KEY_SERVER_PRIVATE.
     * @param devicePublicKey Device public key KEY_DEVICE_PUBLIC.
     * @return Derived transport key KEY_TRANSPORT.
     * @throws InvalidKeyException In case key is invalid.
     * @throws GenericCryptoException In case key derivation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public SecretKey deriveTransportKey(PrivateKey serverPrivateKey, PublicKey devicePublicKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        // Compute master secret key using ECDH
        SecretKey masterSecretKey = generateServerMasterSecretKey(serverPrivateKey, devicePublicKey);
        // Generate server transport key from master secret key
        return generateServerTransportKey(masterSecretKey);
    }

}
