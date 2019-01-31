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
package io.getlime.security.powerauth.crypto.lib.encryptor;

import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.NonPersonalizedEncryptedMessage;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.exception.CryptoProviderException;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * Class responsible for encrypting / decrypting data using non-personalized encryption
 * as documented in PowerAuth 2.0 E2EE documentation.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * Warning: this class will be removed in the future, use ECIES encryption for PowerAuth protocol version 3.0 or higher.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class NonPersonalizedEncryptor {

    private static final int MAX_ATTEMPT_COUNT = 1000;

    private byte[] applicationKey;
    private byte[] sessionIndex;
    private byte[] sessionRelatedSecretKey;
    private byte[] ephemeralPublicKey;

    // Create new working objects
    private final AESEncryptionUtils aes = new AESEncryptionUtils();
    private final KeyGenerator generator = new KeyGenerator();
    private final HMACHashUtilities hmac = new HMACHashUtilities();
    private final CryptoProviderUtil keyConversion = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

    /**
     * Create a new encryptor using provided applicationKey, application master server public key and session index.
     * @param applicationKey Application key.
     * @param sessionRelatedSecretKey Session related derived key.
     * @param sessionIndex Session index used for key derivation.
     * @param ephemeralPublicKeyString Ephemeral public key
     */
    public NonPersonalizedEncryptor(byte[] applicationKey, byte[] sessionRelatedSecretKey, byte[] sessionIndex, byte[] ephemeralPublicKeyString) {
        this.applicationKey = applicationKey;
        this.sessionIndex = sessionIndex;
        this.sessionRelatedSecretKey = sessionRelatedSecretKey;
        this.ephemeralPublicKey = ephemeralPublicKeyString;
    }

    /**
     * Encrypt original data using components in this encryptor.
     * @param originalData Data to be encrypted.
     * @return Message object with encrypted data.
     * @throws InvalidKeyException In case encryption key is invalid.
     * @throws GenericCryptoException In case encryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public NonPersonalizedEncryptedMessage encrypt(byte[] originalData) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        byte[] adHocIndex = generator.generateRandomBytes(16);
        byte[] macIndex = generator.generateRandomBytes(16);

        // make sure the indexes are different
        int attemptCount = 0;
        while (Arrays.equals(adHocIndex, macIndex)) {
            macIndex = generator.generateRandomBytes(16);
            if (attemptCount < MAX_ATTEMPT_COUNT) { // make sure that there is no issue with random data generator
                attemptCount++;
            } else {
                throw new GenericCryptoException("Random byte array generation failed");
            }
        }

        byte[] nonce = generator.generateRandomBytes(16);

        SecretKey sessionKey = keyConversion.convertBytesToSharedSecretKey(this.sessionRelatedSecretKey);
        SecretKey encryptionKey = generator.deriveSecretKeyHmac(sessionKey, adHocIndex);
        SecretKey macKey = generator.deriveSecretKeyHmac(sessionKey, macIndex);

        byte[] encryptedData = aes.encrypt(originalData, nonce, encryptionKey);
        byte[] mac = hmac.hash(macKey, encryptedData);

        NonPersonalizedEncryptedMessage message = new NonPersonalizedEncryptedMessage();
        message.setApplicationKey(applicationKey);
        message.setEphemeralPublicKey(ephemeralPublicKey);
        message.setSessionIndex(sessionIndex);
        message.setAdHocIndex(adHocIndex);
        message.setMacIndex(macIndex);
        message.setNonce(nonce);
        message.setEncryptedData(encryptedData);
        message.setMac(mac);

        return message;
    }

    /**
     * Decrypt the encrypted message from the message payload using this encryptor.
     * @param message Message object to be decrypted.
     * @return Original decrypted bytes.
     * @throws InvalidKeyException In case decryption key is invalid.
     * @throws GenericCryptoException In case decryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] decrypt(NonPersonalizedEncryptedMessage message) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {

        byte[] adHocIndex = message.getAdHocIndex();
        byte[] macIndex = message.getMacIndex();

        // make sure the indexes are different
        if (Arrays.equals(adHocIndex, macIndex)) {
            throw new GenericCryptoException("Invalid index");
        }

        byte[] nonce = message.getNonce();

        SecretKey sessionKey = keyConversion.convertBytesToSharedSecretKey(this.sessionRelatedSecretKey);
        SecretKey encryptionKey = generator.deriveSecretKeyHmac(sessionKey, adHocIndex);
        SecretKey macKey = generator.deriveSecretKeyHmac(sessionKey, macIndex);

        byte[] encryptedData = message.getEncryptedData();

        byte[] macExpected = hmac.hash(macKey, encryptedData);
        byte[] mac = message.getMac();

        // make sure the macs are the same
        if (!Arrays.equals(mac, macExpected)) {
            throw new GenericCryptoException("Invalid mac");
        }

        return aes.decrypt(encryptedData, nonce, encryptionKey);
    }

    public byte[] getApplicationKey() {
        return applicationKey;
    }

    public void setApplicationKey(byte[] applicationKey) {
        this.applicationKey = applicationKey;
    }

    public byte[] getSessionIndex() {
        return sessionIndex;
    }

    public void setSessionIndex(byte[] sessionIndex) {
        this.sessionIndex = sessionIndex;
    }

    public byte[] getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public void setEphemeralPublicKey(byte[] ephemeralPublicKey) {
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    public byte[] getSessionRelatedSecretKey() {
        return sessionRelatedSecretKey;
    }

    public void setSessionRelatedSecretKey(byte[] sessionRelatedSecretKey) {
        this.sessionRelatedSecretKey = sessionRelatedSecretKey;
    }
}
