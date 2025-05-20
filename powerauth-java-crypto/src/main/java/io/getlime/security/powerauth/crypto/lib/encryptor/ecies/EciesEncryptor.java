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
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesPayload;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.crypto.lib.util.EciesUtils;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.crypto.lib.util.KeyConvertor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

/**
 * Class implementing an ECIES encryptor.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class EciesEncryptor {

    private static final Logger logger = LoggerFactory.getLogger(EciesEncryptor.class);

    // Underlying implementation classes.
    private final AESEncryptionUtils aes = new AESEncryptionUtils();
    private final HMACHashUtilities hmac = new HMACHashUtilities();
    private final KeyConvertor keyConvertor = new KeyConvertor();
    private final KeyGenerator keyGenerator = new KeyGenerator();

    // Working data storage
    private final PublicKey publicKey;
    private final byte[] sharedInfo1;
    private final byte[] sharedInfo2;
    private EciesEnvelopeKey envelopeKey;

    // Lifecycle management
    private boolean canEncryptData;

    /**
     * Construct a new encryptor with null sharedInfo1 and sharedInfo2.
     *
     * @param publicKey Public key used for encryption.
     */
    public EciesEncryptor(final ECPublicKey publicKey) {
        this(publicKey, null, null);
    }

    /**
     * Construct a new encryptor with provided sharedInfo1 and sharedInfo2.
     *
     * @param publicKey Public key used for encryption.
     * @param sharedInfo1 Additional shared information used during key derivation.
     * @param sharedInfo2 Additional shared information used during decryption.
     */
    public EciesEncryptor(final ECPublicKey publicKey, final byte[] sharedInfo1, final byte[] sharedInfo2) {
        this.publicKey = publicKey;
        this.sharedInfo1 = sharedInfo1;
        this.sharedInfo2 = sharedInfo2;
        this.canEncryptData = true;
    }

    /**
     * Construct an encryptor from existing ECIES envelope key and sharedInfo2 parameter. The derivation of
     * envelope key is skipped. The privateKey and sharedInfo1 values are unknown.
     *
     * @param envelopeKey ECIES envelope key.
     * @param sharedInfo2 Parameter sharedInfo2 for ECIES.
     */
    public EciesEncryptor(final EciesEnvelopeKey envelopeKey, final byte[] sharedInfo2) {
        this.publicKey = null;
        this.envelopeKey = envelopeKey;
        this.sharedInfo1 = null;
        this.sharedInfo2 = sharedInfo2;
        this.canEncryptData = true;
    }

    /**
     * Initialize envelope key for encryptor using provided ephemeral public key. This method is used when the encryptor
     * parameters are transported over network and the encryptor is reconstructed on another server using envelope key
     * and sharedInfo2 parameter.
     *
     * @param ephemeralPublicKeyBytes Ephemeral public key for ECIES.
     * @throws EciesException In case envelope key initialization fails.
     */
    public void initEnvelopeKey(byte[] ephemeralPublicKeyBytes) throws EciesException {
        envelopeKey = EciesEnvelopeKey.fromPublicKey(publicKey, sharedInfo1);
        // Invalidate this encryptor for encryption
        canEncryptData = false;
    }

    /**
     * Encrypt data.
     *
     * @param data Request data.
     * @param useIv Controls whether encryption uses non-zero initialization vector for protocol V3.1+.
     * @param useTimestamp Controls whether encryption uses timestamp for protocol V3.2+.
     * @param associatedData Associated data for protocol V3.2+ or null for previous protocol versions.
     * @return ECIES payload.
     * @throws EciesException In case encryption fails.
     */
    public EciesPayload encrypt(final byte[] data, final boolean useIv, final boolean useTimestamp, final byte[] associatedData) throws EciesException {
        if (data == null) {
            throw new EciesException("Parameter data for encryption is null");
        }
        if (!canEncrypt()) {
            throw new EciesException("Encryption is not allowed");
        }
        // Derive envelope key, but only in case it does not exist yet
        if (envelopeKey == null) {
            envelopeKey = EciesEnvelopeKey.fromPublicKey(publicKey, sharedInfo1);
        }
        // Generate nonce in case IV is required
        final byte[] nonce = generateNonce(useIv);
        // Generate timestamp in case it is required
        Long timestamp = null;
        if (useTimestamp) {
            timestamp = EciesUtils.generateTimestamp();
        }
        return encryptInternal(data, nonce, timestamp, associatedData);
    }

    /**
     * Encrypt data with provided ECIES parameters.
     *
     * @param data Request data.
     * @param eciesParameters ECIES parameters.
     * @return ECIES payload.
     * @throws EciesException In case encryption fails.
     */
    public EciesPayload encrypt(final byte[] data, final EciesParameters eciesParameters) throws EciesException {
        if (data == null) {
            throw new EciesException("Parameter data for encryption is null");
        }
        if (eciesParameters == null) {
            throw new EciesException("Parameter eciesParameters for encryption is null");
        }
        if (!canEncrypt()) {
            throw new EciesException("Encryption is not allowed");
        }
        // Derive envelope key, but only in case it does not exist yet
        if (envelopeKey == null) {
            envelopeKey = EciesEnvelopeKey.fromPublicKey(publicKey, sharedInfo1);
        }
        final byte[] associatedData = eciesParameters.getAssociatedData();
        final Long timestamp = eciesParameters.getTimestamp();
        return encryptInternal(data, eciesParameters.getNonce(), timestamp, associatedData);
    }
    /**
     * Get parameter sharedInfo2 for ECIES.
     * @return Parameter sharedInfo2 for ECIES.
     */
    public byte[] getSharedInfo2() {
        return sharedInfo2;
    }

    /**
     * Get ECIES envelope key.
     * @return ECIES envelope key.
     */
    public EciesEnvelopeKey getEnvelopeKey() {
        return envelopeKey;
    }

    /**
     * Get whether request data can be encrypted.
     *
     * @return Whether request data can be encrypted.
     */
    private boolean canEncrypt() {
        return canEncryptData && (publicKey != null || (envelopeKey != null && envelopeKey.isValid()));
    }

    /**
     * Encrypt data using ECIES and construct ECIES payload.
     *
     * @param data Data to be encrypted.
     * @param nonce Nonce for protocol V3.1+ or null for previous protocol versions.
     * @param timestamp Timestamp for protocol V3.2+ or null for previous protocol versions.
     * @param associatedData Associated data for protocol V3.2+ or null for previous protocol versions.
     * @return ECIES payload.
     * @throws EciesException In case AES encryption fails.
     */
    private EciesPayload encryptInternal(final byte[] data, final byte[] nonce, final Long timestamp, final byte[] associatedData) throws EciesException {
        try {

            // Encrypt the data with
            byte[] encKeyBytes = envelopeKey.getEncKey();
            final SecretKey encKey = keyConvertor.convertBytesToSharedSecretKey(encKeyBytes);
            byte[] iv;
            if (nonce != null) {
                iv = envelopeKey.deriveIvForNonce(nonce);
            } else {
                iv = new byte[16];
            }
            final byte[] encryptedData = aes.encrypt(data, iv, encKey);

            // Resolve MAC data based on protocol version
            final byte[] macData = EciesUtils.generateMacData(sharedInfo2, encryptedData);

            // Compute data MAC
            final byte[] mac = hmac.hash(envelopeKey.getMacKey(), macData);

            // Invalidate this encryptor
            canEncryptData = false;

            // Return encrypted payload
            final EciesCryptogram cryptogram = EciesCryptogram.builder()
                    .ephemeralPublicKey(envelopeKey.getEphemeralKeyPublic())
                    .mac(mac)
                    .encryptedData(encryptedData)
                    .build();
            final EciesParameters parameters = EciesParameters.builder()
                    .nonce(nonce)
                    .associatedData(associatedData)
                    .timestamp(timestamp)
                    .build();
            return new EciesPayload(cryptogram, parameters);
        } catch (InvalidKeyException | GenericCryptoException | CryptoProviderException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new EciesException("Encryption failed", ex);
        }
    }

    /**
     * Generate nonce based on requirement to use non-null IV.
     * @param useIv Whether non-null IV should be used.
     * @return Nonce.
     * @throws EciesException Thrown in case nonce could not be generated.
     */
    private byte[] generateNonce(boolean useIv) throws EciesException {
        if (useIv) {
            // V3.1+, generate random nonce and calculate IV
            try {
                return keyGenerator.generateRandomBytes(16);
            } catch (CryptoProviderException ex) {
                logger.warn(ex.getMessage(), ex);
                throw new EciesException("Encryption failed", ex);
            }
        }
        // V2.x, V3.0, use zero IV
        return null;
    }

}
