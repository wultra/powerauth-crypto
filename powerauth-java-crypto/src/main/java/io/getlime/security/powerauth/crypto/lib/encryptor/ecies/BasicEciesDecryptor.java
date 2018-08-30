/*
 * Copyright 2017 Wultra s.r.o.
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
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.kdf.KdfX9_63;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesPayload;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.crypto.lib.util.HMACHashUtilities;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * Basic ECIES decryptor class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class BasicEciesDecryptor {

    // Underlying implementation classes
    private final AESEncryptionUtils aes = new AESEncryptionUtils();
    private final HMACHashUtilities hmac = new HMACHashUtilities();
    private final KeyGenerator keyGenerator = new KeyGenerator();
    private final CryptoProviderUtil keyConverter = PowerAuthConfiguration.INSTANCE.getKeyConvertor();

    // Encryptor working data storage
    private final PrivateKey privateKey;
    private final byte[] sharedInfo2;
    private PublicKey ephemeralPublicKey;

    // Life-cycle management variables
    private boolean canDecryptData;
    private boolean canEncryptData;

    /**
     * Constructs a new decryptor with the base private key and null sharedInfo2.
     *
     * @param encryptionPrivateKey Private key to be used for decryption.
     */
    public BasicEciesDecryptor(ECPrivateKey encryptionPrivateKey) {
        this(encryptionPrivateKey, null);
    }

    /**
     * Constructs a new decryptor with the base private key and provided sharedInfo2.
     *
     * @param encryptionPrivateKey Private key to be used for decryption.
     * @param sharedInfo2 Extra data used as "sharedInfo2" attribute during decription.
     */
    public BasicEciesDecryptor(ECPrivateKey encryptionPrivateKey, byte[] sharedInfo2) {
        this.privateKey = encryptionPrivateKey;
        this.sharedInfo2 = sharedInfo2;
        this.canDecryptData = true;
        this.canEncryptData = false;
    }

    /**
     * Decrypt provided encrypted payload.
     *
     * @param payload Payload to be decrypted.
     * @param info Additional information that enters the KDF function.
     * @return Decrypted bytes.
     * @throws EciesException In case decryption fails due to invalid life-cycle phase, invalid key or invalid MAC value.
     */
    public byte[] decrypt(EciesPayload payload, byte[] info) throws EciesException {
        try {
            if (!canDecryptData) {
                throw new EciesException("This decryptor instance was already used");
            }

            // Store the ephemeral public key
            ephemeralPublicKey = payload.getEphemeralPublicKey();

            // Derive secret key
            final SecretKey secretKey = keyGenerator.computeSharedKey(privateKey, ephemeralPublicKey, true);
            final byte[] ephemeralDerivedSecretKey = KdfX9_63.derive(keyConverter.convertSharedSecretKeyToBytes(secretKey), info, 32);

            // Validate data MAC value
            final byte[] macKeyBytes = Arrays.copyOfRange(ephemeralDerivedSecretKey, 16, 32);
            final byte[] macData = (sharedInfo2 == null ? payload.getEncryptedData() : Bytes.concat(payload.getEncryptedData(), sharedInfo2));
            final byte[] mac = hmac.hash(macKeyBytes, macData);
            if (!Arrays.equals(mac, payload.getMac())) {
                throw new EciesException("Invalid MAC");
            }

            // Decrypt the data
            final byte[] encKeyBytes = Arrays.copyOf(ephemeralDerivedSecretKey, 16);
            final SecretKey encKey = keyConverter.convertBytesToSharedSecretKey(encKeyBytes);
            final byte[] iv = new byte[16];

            // Invalidate this decryptor for decryption.
            canDecryptData = false;
            canEncryptData = true;

            return aes.decrypt(payload.getEncryptedData(), iv, encKey);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new EciesException("Decryption error occurred", e);
        }
    }

    /**
     * Encrypt data using the same base key that was used for previous decryption. Useful when handling the
     * "request/response" cycle of the app.
     * @param data Data to be encrypted.
     * @param info Additional information that enters the KDF function.
     * @return Encrypted data.
     * @throws EciesException In case data could not be encrypted due to invalid key or invalid lifecycle phase.
     */
    public EciesPayload encrypt(byte[] data, byte[] info) throws EciesException {
        try {
            if (!canEncryptData) {
                throw new EciesException("This decryptor instance was already used");
            }

            // Derive secret key
            final SecretKey secretKey = keyGenerator.computeSharedKey(privateKey, ephemeralPublicKey, true);
            final byte[] ephemeralDerivedSecretKey = KdfX9_63.derive(keyConverter.convertSharedSecretKeyToBytes(secretKey), info, 32);

            // Encrypt the data
            final byte[] encKeyBytes = Arrays.copyOf(ephemeralDerivedSecretKey, 16);
            final SecretKey encKey = keyConverter.convertBytesToSharedSecretKey(encKeyBytes);
            final byte[] iv = new byte[16];
            final byte[] body = aes.encrypt(data, iv, encKey);

            // Compute MAC of the data
            final byte[] macKeyBytes = Arrays.copyOfRange(ephemeralDerivedSecretKey, 16, 32);
            final byte[] macData = (sharedInfo2 == null ? body : Bytes.concat(body, sharedInfo2));
            final byte[] mac = hmac.hash(macKeyBytes, macData);

            // invalidate this decryptor
            canEncryptData = false;

            // Return encrypted payload
            return new EciesPayload(ephemeralPublicKey, mac, body);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new EciesException("Decryption error occurred", e);
        }
    }

    /**
     * Encrypt data using the same base key that was used for previous decryption. Use provided ephemeral public key.
     * Useful when handling the "request/response" cycle of the app in situation client request only sends an ephemeral
     * public key, without any MAC and data.
     *
     * @param data Data to be encrypted.
     * @param ephemeralPublicKey Ephemeral public key used for encryption.
     * @param info Additional information that enters the KDF function.
     * @return Encrypted data.
     * @throws EciesException In case data could not be encrypted due to invalid key or invalid lifecycle phase.
     */
    public EciesPayload encrypt(byte[] data, ECPublicKey ephemeralPublicKey, byte[] info) throws EciesException {
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.canDecryptData = false;
        this.canEncryptData = true;
        return encrypt(data, info);
    }

}
