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
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;

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
    private final KeyConvertor keyConvertor = new KeyConvertor();

    // Encryptor working data storage
    private final PrivateKey privateKey;
    private final byte[] sharedInfo1;
    private final byte[] sharedInfo2;
    private EciesEnvelopeKey envelopeKey;

    // Life-cycle management variables
    private boolean canDecryptData;

    /**
     * Construct a new decryptor with the base private key and null sharedInfo1 and sharedInfo2 parameters.
     *
     * @param encryptionPrivateKey Private key to be used for decryption.
     */
    public EciesDecryptor(final ECPrivateKey encryptionPrivateKey) {
        this(encryptionPrivateKey, null, null);
    }

    /**
     * Construct a new decryptor with the base private key and provided sharedInfo1 and sharedInfo2 parameters.
     *
     * @param encryptionPrivateKey Private key to be used for decryption.
     * @param sharedInfo1 Additional shared information used during key derivation.
     * @param sharedInfo2 Additional shared information used during decryption.
     */
    public EciesDecryptor(final ECPrivateKey encryptionPrivateKey, final byte[] sharedInfo1, final byte[] sharedInfo2) {
        this.privateKey = encryptionPrivateKey;
        this.sharedInfo1 = sharedInfo1;
        this.sharedInfo2 = sharedInfo2;
        this.canDecryptData = true;
    }

    /**
     * Construct a decryptor from existing ECIES envelope key and sharedInfo2 parameter. The derivation of
     * envelope key is skipped. The privateKey and sharedInfo1 values are unknown.
     *
     * @param envelopeKey ECIES envelope key.
     * @param sharedInfo2 Parameter sharedInfo2 for ECIES.
     */
    public EciesDecryptor(final EciesEnvelopeKey envelopeKey, final byte[] sharedInfo2) {
        this.privateKey = null;
        this.envelopeKey = envelopeKey;
        this.sharedInfo1 = null;
        this.sharedInfo2 = sharedInfo2;
        // Allow decrypt to support decryption with provided envelope key and sharedInfo2 and response encryption
        this.canDecryptData = true;
    }

    /**
     * Initialize envelope key for decryptor using provided ephemeral public key. This method is used either when
     * there is no incoming encrypted request to decrypt which would initialize the envelope key or the decryptor
     * parameters are transported over network and the decryptor is reconstructed on another server using envelope key
     * and sharedInfo2 parameter.
     *
     * @param ephemeralPublicKeyBytes Ephemeral public key for ECIES.
     * @throws EciesException In case envelope key initialization fails.
     */
    public void initEnvelopeKey(byte[] ephemeralPublicKeyBytes) throws EciesException {
        envelopeKey = EciesEnvelopeKey.fromPrivateKey(privateKey, ephemeralPublicKeyBytes, sharedInfo1);
        // Invalidate this decryptor for decryption
        canDecryptData = false;
    }

    /**
     * Decrypt data from ECIES payload.
     *
     * @param payload ECIES payload.
     * @return Decrypted data.
     * @throws EciesException In case decryption fails.
     */
    public byte[] decrypt(final EciesPayload payload) throws EciesException {
        final EciesCryptogram cryptogram = payload.getCryptogram();
        final EciesParameters parameters = payload.getParameters();
        final boolean requireIv = parameters.getNonce() != null;
        if (cryptogram == null || cryptogram.getEncryptedData() == null || cryptogram.getMac() == null || (envelopeKey == null && cryptogram.getEphemeralPublicKey() == null)) {
            throw new EciesException("Parameter cryptogram for decryption is invalid");
        }
        if (!canDecrypt()) {
            throw new EciesException("Decryption is not allowed");
        }
        // Derive envelope key, but only in case it does not exist yet
        if (envelopeKey == null) {
            envelopeKey = EciesEnvelopeKey.fromPrivateKey(privateKey, cryptogram.getEphemeralPublicKey(), sharedInfo1);
        }
        return decryptInternal(payload, requireIv);
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
    private boolean canDecrypt() {
        // For decryption either private key must exist or the envelope key must exist and be valid
        return canDecryptData && (privateKey != null || (envelopeKey != null && envelopeKey.isValid()));
    }

    /**
     * Decrypt provided encrypted payload.
     *
     * @param payload ECIES payload to be decrypted.
     * @param requireIv Determines whether non-zero IV is used for decryption and encryption. This is required for protocol V3.1 and later.
     * @return Decrypted data.
     * @throws EciesException In case MAC value is invalid or AES decryption fails.
     */
    private byte[] decryptInternal(final EciesPayload payload, final boolean requireIv) throws EciesException {
        try {
            // Resolve MAC data based on protocol version
            final EciesCryptogram cryptogram = payload.getCryptogram();
            final EciesParameters parameters = payload.getParameters();
            final byte[] macData = EciesUtils.generateMacData(sharedInfo2, cryptogram.getEncryptedData());

            // Validate data MAC value
            final byte[] mac = hmac.hash(envelopeKey.getMacKey(), macData);
            if (!SideChannelUtils.constantTimeAreEqual(mac, cryptogram.getMac())) {
                throw new EciesException("Invalid MAC");
            }

            // Decrypt the data with AES
            final byte[] encKeyBytes = envelopeKey.getEncKey();
            final SecretKey encKey = keyConvertor.convertBytesToSharedSecretKey(encKeyBytes);
            final byte[] iv = requireIv ? envelopeKey.deriveIvForNonce(parameters.getNonce()) : new byte[16];

            // Invalidate this decryptor
            canDecryptData = false;

            return aes.decrypt(cryptogram.getEncryptedData(), iv, encKey);
        } catch (InvalidKeyException | GenericCryptoException | CryptoProviderException ex) {
            logger.warn(ex.getMessage(), ex);
            throw new EciesException("Decryption failed", ex);
        }
    }

}
