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
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.*;
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
    private boolean canDecryptData;
    private byte[] ivForDecryption;


    /**
     * Construct a new encryptor with null sharedInfo1 and sharedInfo2.
     *
     * @param publicKey Public key used for encryption.
     */
    public EciesEncryptor(ECPublicKey publicKey) {
        this(publicKey, null, null);
    }

    /**
     * Construct a new encryptor with provided sharedInfo1 and sharedInfo2.
     *
     * @param publicKey Public key used for encryption.
     * @param sharedInfo1 Additional shared information used during key derivation.
     * @param sharedInfo2 Additional shared information used during decryption.
     */
    public EciesEncryptor(ECPublicKey publicKey, byte[] sharedInfo1, byte[] sharedInfo2) {
        this.publicKey = publicKey;
        this.sharedInfo1 = sharedInfo1;
        this.sharedInfo2 = sharedInfo2;
        this.canEncryptData = true;
        this.canDecryptData = false;
    }

    /**
     * Construct an encryptor from existing ECIES envelope key and sharedInfo2 parameter. The derivation of
     * envelope key is skipped. The privateKey and sharedInfo1 values are unknown. The encryptor can be only
     * used for decrypting the response.
     *
     * @param envelopeKey ECIES envelope key.
     * @param sharedInfo2 Parameter sharedInfo2 for ECIES.
     */
    public EciesEncryptor(EciesEnvelopeKey envelopeKey, byte[] sharedInfo2) {
        this.publicKey = null;
        this.envelopeKey = envelopeKey;
        this.sharedInfo1 = null;
        this.sharedInfo2 = sharedInfo2;
        // Allow decrypt only to avoid accidentally reusing the same encryptor for encryption, a new envelope key with
        // a new ephemeral keypair is always generated for encryption.
        this.canEncryptData = false;
        this.canDecryptData = true;
    }

    /**
     * Encrypt request data.
     *
     * @param data Request data.
     * @param useIv Controls whether encryption uses non-zero initialization vector for protocol V3.1+.
     * @param associatedData Associated data for protocol V3.2+ or null for previous protocol versions.
     * @return ECIES cryptogram.
     * @throws EciesException In case request encryption fails.
     */
    public EciesCryptogram encryptRequest(byte[] data, boolean useIv, byte[] associatedData) throws EciesException {
        if (data == null) {
            throw new EciesException("Parameter data for request encryption is null");
        }
        if (!canEncryptRequest()) {
            throw new EciesException("Request encryption is not allowed");
        }
        envelopeKey = EciesEnvelopeKey.fromPublicKey(publicKey, sharedInfo1);
        return encrypt(data, useIv, associatedData);
    }

    /**
     * Decrypt response data.
     *
     * @param cryptogram ECIES cryptogram.
     * @return Decrypted data.
     * @throws EciesException In case response decryption fails.
     */
    public byte[] decryptResponse(EciesCryptogram cryptogram) throws EciesException {
        if (cryptogram == null || cryptogram.getEncryptedData() == null || cryptogram.getMac() == null) {
            throw new EciesException("Parameter cryptogram for response decryption is invalid");
        }
        if (!canDecryptResponse()) {
            throw new EciesException("Response decryption is not allowed");
        }
        return decrypt(cryptogram);
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
    private boolean canEncryptRequest() {
        return canEncryptData && publicKey != null;
    }

    /**
     * Get whether response data can be decrypted.
     *
     * @return Whether response data can be decrypted.
     */
    private boolean canDecryptResponse() {
        return canDecryptData && envelopeKey.isValid() && ivForDecryption != null;
    }

    /**
     * Encrypt data using ECIES and construct ECIES cryptogram.
     *
     * @param data Data to be encrypted.
     * @param useIv Controls whether encryption uses non-zero initialization vector for protocol V3.1+.
     * @param associatedData Associated data for protocol V3.2+ or null for previous protocol versions.
     * @return Encrypted data as cryptogram.
     * @throws EciesException In case AES encryption fails.
     */
    private EciesCryptogram encrypt(byte[] data, boolean useIv, byte[] associatedData) throws EciesException {
        try {
            // Prepare nonce & IV
            final byte[] nonce;
            final byte[] iv;
            if (useIv) {
                // V3.1+, generate random nonce and calculate IV
                nonce = keyGenerator.generateRandomBytes(16);
                iv = envelopeKey.deriveIvForNonce(nonce);
            } else {
                // V2.x, V3.0, use zero IV
                nonce = null;
                iv = new byte[16];
            }
            // Encrypt the data with
            byte[] encKeyBytes = envelopeKey.getEncKey();
            final SecretKey encKey = keyConvertor.convertBytesToSharedSecretKey(encKeyBytes);
            final byte[] encryptedData = aes.encrypt(data, iv, encKey);

            // Resolve timestamp based on protocol version
            byte[] timestampBytes = EciesUtils.resolveTimestamp(associatedData);

            // Resolve MAC data based on protocol version
            final byte[] macData = EciesUtils.resolveMacData(sharedInfo2, encryptedData, nonce,
                    associatedData, timestampBytes, envelopeKey.getEphemeralKeyPublic());

            // Compute data MAC
            final byte[] mac = hmac.hash(envelopeKey.getMacKey(), macData);

            // Invalidate this encryptor for encryption
            canEncryptData = false;
            canDecryptData = true;
            ivForDecryption = iv;

            // Return encrypted payload
            return new EciesCryptogram(envelopeKey.getEphemeralKeyPublic(), mac, encryptedData, nonce, associatedData, timestampBytes);
        } catch (InvalidKeyException | GenericCryptoException | CryptoProviderException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new EciesException("Request encryption failed", ex);
        }
    }

    /**
     * Decrypt provided payload using ECIES algorithm and the same secret key as in previous encrypt call, useful for
     * request-response cycle.
     *
     * @param cryptogram Cryptogram to be decrypted.
     * @return Decrypted data.
     * @throws EciesException In case MAC value is invalid or AES decryption fails.
     */
    private byte[] decrypt(EciesCryptogram cryptogram) throws EciesException {
        try {
            // Resolve MAC data based on protocol version
            final byte[] macData = EciesUtils.resolveMacData(sharedInfo2, cryptogram.getEncryptedData(), cryptogram.getNonce(),
                    cryptogram.getAssociatedData(), cryptogram.getTimestamp(), cryptogram.getEphemeralPublicKey());

            // Validate data MAC value
            final byte[] mac = hmac.hash(envelopeKey.getMacKey(), macData);
            if (!SideChannelUtils.constantTimeAreEqual(mac, cryptogram.getMac())) {
                throw new EciesException("Invalid MAC");
            }

            // Decrypt the data with AES using specified IV
            final byte[] encKeyBytes = envelopeKey.getEncKey();
            final SecretKey encKey = keyConvertor.convertBytesToSharedSecretKey(encKeyBytes);
            final byte[] iv = ivForDecryption;

            // Invalidate the encryptor
            canDecryptData = false;
            ivForDecryption = null;

            return aes.decrypt(cryptogram.getEncryptedData(), iv, encKey);
        } catch (InvalidKeyException | GenericCryptoException | CryptoProviderException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new EciesException("Response decryption failed", ex);
        }
    }
}
