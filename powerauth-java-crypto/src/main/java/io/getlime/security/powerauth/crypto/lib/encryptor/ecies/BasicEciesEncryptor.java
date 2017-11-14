/*
 * Copyright 2017 Lime - HighTech Solutions s.r.o.
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
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * Class implementing a basic ECIES encryptor.
 * The class uses X9.63+SHA256 for internal KDF.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class BasicEciesEncryptor {

    // Underlying implementation classes.
    private AESEncryptionUtils aes = new AESEncryptionUtils();
    private HMACHashUtilities hmac = new HMACHashUtilities();
    private CryptoProviderUtil keyConverter = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
    private KeyGenerator keyGenerator = new KeyGenerator();

    // Working data storage
    private PublicKey publicKey;
    private byte[] ephemeralDerivedSecretKey;
    private byte[] sharedInfo2;

    // Lifecycle management
    private boolean canEncryptData;
    private boolean canDecryptData;

    /**
     * Create basic ECIES encryptor with null sharedInfo2.
     * @param publicKey Public key used for encryption.
     */
    public BasicEciesEncryptor(ECPublicKey publicKey) {
        this(publicKey, null);
    }

    /**
     * Create basic ECIES encryptor with provided sharedInfo2.
     * @param publicKey Public key used for encryption.
     * @param sharedInfo2 Additional information as sharedInfo2
     */
    public BasicEciesEncryptor(ECPublicKey publicKey, byte[] sharedInfo2) {
        this.publicKey = publicKey;
        this.sharedInfo2 = sharedInfo2;
        this.canEncryptData = true;
        this.canDecryptData = false;
    }

    /**
     * Encrypt data using ECIES with instance public key and additional info for KDF function.
     * @param data Data to be encrypted.
     * @param info Additional info for KDF.
     * @return Encrypted data.
     * @throws EciesException In case data encryption fails due to invalid key.
     */
    public EciesPayload encrypt(byte[] data, byte[] info) throws EciesException {
        try {
            if (!canEncryptData) {
                throw new EciesException("This encryptor instance was already used");
            }

            // Generate ephemeral keypair and derive
            // ephemeral encryption key
            final KeyPair ephemeralKeyPair = keyGenerator.generateKeyPair();
            final PrivateKey ephemeralKeyPrivate = ephemeralKeyPair.getPrivate();

            // Store the data inside th instance
            PublicKey ephemeralPublicKey = ephemeralKeyPair.getPublic();
            SecretKey ephemeralSecretKey = keyGenerator.computeSharedKey(ephemeralKeyPrivate, publicKey, true);
            ephemeralDerivedSecretKey = KdfX9_63.derive(keyConverter.convertSharedSecretKeyToBytes(ephemeralSecretKey), info, 32);


            // Encrypt the data
            byte[] encKeyBytes = Arrays.copyOf(ephemeralDerivedSecretKey, 16);
            final SecretKey encKey = keyConverter.convertBytesToSharedSecretKey(encKeyBytes);
            byte[] iv = new byte[16];
            final byte[] body = aes.encrypt(data, iv, encKey);

            // Compute MAC of the data
            byte[] macKeyBytes = Arrays.copyOfRange(ephemeralDerivedSecretKey, 16, 32);
            byte[] macData = (sharedInfo2 == null ? body : Bytes.concat(body, sharedInfo2));
            final byte[] mac = hmac.hash(macKeyBytes, macData);

            // Invalidate the encryptor instance
            canEncryptData = false;
            canDecryptData = true;

            // Return encrypted payload
            return new EciesPayload(ephemeralPublicKey, mac, body);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new EciesException("Decryption error occurred", e);
        }
    }

    /**
     * Decrypt provided payload using ECIES algorithm and the same key as in previous encrypt call, useful for
     * request-response cycle.
     * @param payload Payload to be decrypted.
     * @return Decrypted data.
     * @throws EciesException In case MAC is incorrect or in case invalid key was provided.
     */
    public byte[] decrypt(EciesPayload payload) throws EciesException {
        try {
            if (!canDecryptData) {
                throw new EciesException("This encryptor instance was already used");
            }

            // Validate data MAC value
            byte[] macKeyBytes = Arrays.copyOfRange(ephemeralDerivedSecretKey, 16, 32);
            byte[] macData = (sharedInfo2 == null ? payload.getEncryptedData() : Bytes.concat(payload.getEncryptedData(), sharedInfo2));
            final byte[] mac = hmac.hash(macKeyBytes, macData);
            if (!Arrays.equals(mac, payload.getMac())) {
                throw new EciesException("Invalid MAC");
            }

            // Decrypt the data
            byte[] encKeyBytes = Arrays.copyOf(ephemeralDerivedSecretKey, 16);
            final SecretKey encKey = keyConverter.convertBytesToSharedSecretKey(encKeyBytes);
            byte[] iv = new byte[16];

            // Invalidate the encryptor
            canDecryptData = false;

            return aes.decrypt(payload.getEncryptedData(), iv, encKey);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            throw new EciesException("Decryption error occurred", e);
        }
    }

}
