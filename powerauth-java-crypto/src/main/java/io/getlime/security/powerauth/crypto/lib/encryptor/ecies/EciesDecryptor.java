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

import com.google.common.primitives.Bytes;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.provider.exception.CryptoProviderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;

/**
 * Class implementing an ECIES decryptor.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class EciesDecryptor {

    private static final Logger logger = LoggerFactory.getLogger(EciesDecryptor.class);

    // Underlying implementation classes
    private final AESEncryptionUtils aes = new AESEncryptionUtils();
    private final HMACHashUtilities hmac = new HMACHashUtilities();
    private final CryptoProviderUtil keyConverter = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

    // Encryptor working data storage
    private final PrivateKey privateKey;
    private final byte[] sharedInfo1;
    private final byte[] sharedInfo2;
    private EciesEnvelopeKey envelopeKey;

    // Life-cycle management variables
    private boolean canDecryptData;
    private boolean canEncryptData;
    private byte[] ivForEncryption;

    /**
     * Construct a new decryptor with the base private key and null sharedInfo1 and sharedInfo2 parameters.
     *
     * @param encryptionPrivateKey Private key to be used for decryption.
     */
    public EciesDecryptor(ECPrivateKey encryptionPrivateKey) {
        this(encryptionPrivateKey, null, null);
    }

    /**
     * Construct a new decryptor with the base private key and provided sharedInfo1 and sharedInfo2 parameters.
     *
     * @param encryptionPrivateKey Private key to be used for decryption.
     * @param sharedInfo1 Additional shared information used during key derivation.
     * @param sharedInfo2 Additional shared information used during decryption.
     */
    public EciesDecryptor(ECPrivateKey encryptionPrivateKey, byte[] sharedInfo1, byte[] sharedInfo2) {
        this.privateKey = encryptionPrivateKey;
        this.sharedInfo1 = sharedInfo1;
        this.sharedInfo2 = sharedInfo2;
        this.canDecryptData = true;
        this.canEncryptData = false;
    }

    /**
     * Construct a decryptor from existing ECIES envelope key and sharedInfo2 parameter. The derivation of
     * envelope key is skipped. The privateKey and sharedInfo1 values are unknown.
     *
     * @param envelopeKey ECIES envelope key.
     * @param sharedInfo2 Parameter sharedInfo2 for ECIES.
     */
    public EciesDecryptor(EciesEnvelopeKey envelopeKey, byte[] sharedInfo2) {
        this.privateKey = null;
        this.envelopeKey = envelopeKey;
        this.sharedInfo1 = null;
        this.sharedInfo2 = sharedInfo2;
        // Allow decrypt to support request decryption with provided envelope key and sharedInfo2
        this.canDecryptData = true;
        this.canEncryptData = false;
    }

    /**
     * Initialize envelope key for decryptor using provided ephemeral public key. This method is used either when there
     * is no incoming encrypted request to decrypt which would initialize the envelope key or the decryptor parameters
     * are transported over network and the decryptor is reconstructed on another server using envelope key
     * and sharedInfo2 parameter.
     *
     * @param ephemeralPublicKeyBytes Ephemeral public key for ECIES.
     * @param nonce Nonce required for the future response encryption. The parameter may be {@code null} for a legacy V2 ECIES encryption,
     *              or if the only purpose of the initialization is to generate parameters, for the remote decryptor.
     * @throws EciesException In case envelope key initialization fails.
     */
    public void initEnvelopeKey(byte[] ephemeralPublicKeyBytes, byte[] nonce) throws EciesException {
        envelopeKey = EciesEnvelopeKey.fromPrivateKey(privateKey, ephemeralPublicKeyBytes, sharedInfo1);
        // Invalidate this decryptor for decryption
        canDecryptData = false;
        canEncryptData = true;
        // Derive IV for future encryption.
        ivForEncryption = nonce != null ? envelopeKey.deriveIvForNonce(nonce) : new byte[16];
    }

    /**
     * Decrypt request data from cryptogram.
     *
     * @param cryptogram ECIES cryptogram.
     * @param requireIv Determines whether non-zero IV is used for decryption and encryption. This is required for protocol V3.1 and later.
     * @return Decrypted data.
     * @throws EciesException In case request decryption fails.
     */
    public byte[] decryptRequest(EciesCryptogram cryptogram, boolean requireIv) throws EciesException {
        if (cryptogram == null || cryptogram.getEncryptedData() == null || cryptogram.getMac() == null || (envelopeKey == null && cryptogram.getEphemeralPublicKey() == null)) {
            throw new EciesException("Parameter cryptogram for request decryption is invalid");
        }
        if (requireIv && cryptogram.getNonce() == null) {
            throw new EciesException("Nonce parameter in cryptogram is invalid.");
        }
        if (!canDecryptRequest()) {
            throw new EciesException("Request decryption is not allowed");
        }
        // Derive envelope key, but only in case it does not exist yet
        if (envelopeKey == null) {
            envelopeKey = EciesEnvelopeKey.fromPrivateKey(privateKey, cryptogram.getEphemeralPublicKey(), sharedInfo1);
        }
        return decrypt(cryptogram, requireIv);
    }

    /**
     * Decrypt request data from cryptogram. The function automatically determines whether the cryptogram contains
     * the nonce parameter and then selects an appropriate configuration for initialization vector.
     *
     * @param cryptogram ECIES cryptogram.
     * @return Decrypted data.
     * @throws EciesException In case request decryption fails.
     */
    public byte[] decryptRequest(EciesCryptogram cryptogram) throws EciesException {
        return decryptRequest(cryptogram, cryptogram.getNonce() != null);
    }

    /**
     * Encrypt response data and construct ECIES cryptogram. Use when the {@link #decryptRequest} method was
     * already called and the ECIES envelope key is already derived.
     *
     * @param data Response data to encrypt.
     * @return ECIES cryptogram.
     * @throws EciesException In case response encryption fails.
     */
    public EciesCryptogram encryptResponse(byte[] data) throws EciesException {
        if (data == null) {
            throw new EciesException("Parameter data for response encryption is null");
        }
        if (!canEncryptResponse()) {
            throw new EciesException("Response encryption is not allowed");
        }
        return encrypt(data);
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
     * Get whether request data can be decrypted.
     *
     * @return Whether request data can be decrypted.
     */
    private boolean canDecryptRequest() {
        // For decryption either private key must exist or the envelope key must exist and be valid
        return canDecryptData && (privateKey != null || (envelopeKey != null && envelopeKey.isValid()));
    }

    /**
     * Get whether response data can be encrypted.
     *
     * @return Whether data can be encrypted.
     */
    private boolean canEncryptResponse() {
        return canEncryptData && envelopeKey.isValid() && ivForEncryption != null;
    }

    /**
     * Decrypt provided encrypted cryptogram.
     *
     * @param cryptogram ECIES cryptogram to be decrypted.
     * @param requireIv Determines whether non-zero IV is used for decryption and encryption. This is required for protocol V3.1 and later.
     * @return Decrypted data.
     * @throws EciesException In case MAC value is invalid or AES decryption fails.
     */
    private byte[] decrypt(EciesCryptogram cryptogram, boolean requireIv) throws EciesException {
        try {
            // Validate data MAC value
            final byte[] macData = (sharedInfo2 == null ? cryptogram.getEncryptedData() : Bytes.concat(cryptogram.getEncryptedData(), sharedInfo2));
            final byte[] mac = hmac.hash(envelopeKey.getMacKey(), macData);
            if (!Arrays.equals(mac, cryptogram.getMac())) {
                throw new EciesException("Invalid MAC");
            }

            // Decrypt the data with AES
            final byte[] encKeyBytes = envelopeKey.getEncKey();
            final SecretKey encKey = keyConverter.convertBytesToSharedSecretKey(encKeyBytes);
            final byte[] iv = requireIv ? envelopeKey.deriveIvForNonce(cryptogram.getNonce()) : new byte[16];

            // Invalidate this decryptor for decryption
            canDecryptData = false;
            canEncryptData = true;
            ivForEncryption = iv;

            return aes.decrypt(cryptogram.getEncryptedData(), iv, encKey);
        } catch (InvalidKeyException | GenericCryptoException | CryptoProviderException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new EciesException("Request decryption failed", ex);
        }
    }

    /**
     * Encrypt data using the same envelope key that was used for previous decryption. Useful when handling the
     * "request/response" cycle of the app.
     *
     * @param data Data to be encrypted.
     * @return Encrypted data as ECIES cryptogram.
     * @throws EciesException In case AES encryption fails.
     */
    private EciesCryptogram encrypt(byte[] data) throws EciesException {
        try {
            // Encrypt the data with AES using zero IV
            final byte[] encKeyBytes = envelopeKey.getEncKey();
            final SecretKey encKey = keyConverter.convertBytesToSharedSecretKey(encKeyBytes);
            final byte[] iv = ivForEncryption;
            final byte[] body = aes.encrypt(data, iv, encKey);

            // Compute MAC of the data
            final byte[] macData = (sharedInfo2 == null ? body : Bytes.concat(body, sharedInfo2));
            final byte[] mac = hmac.hash(envelopeKey.getMacKey(), macData);

            // Invalidate this decryptor
            canEncryptData = false;
            ivForEncryption = null;

            // Return encrypted payload
            return new EciesCryptogram(envelopeKey.getEphemeralKeyPublic(), mac, body, null);
        } catch (InvalidKeyException | GenericCryptoException | CryptoProviderException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new EciesException("Response encryption failed", ex);
        }
    }

}
