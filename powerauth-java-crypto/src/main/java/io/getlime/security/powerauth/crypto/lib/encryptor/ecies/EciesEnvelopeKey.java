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

import com.google.common.primitives.Bytes;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.kdf.KdfX9_63;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * The ECIES Envelope Key represents a temporary key for ECIES encryption and decryption
 * process. The key is derived from shared secret produced in ECDH key agreement.
 * The derivation function is X9.63 with SHA256 digest. Additionally this class holds the ephemeral public key
 * which is either generated or received from the client.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class EciesEnvelopeKey {

    private static final int ENVELOPE_KEY_SIZE = 32;

    private static final CryptoProviderUtil keyConverter = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
    private static final KeyGenerator keyGenerator = new KeyGenerator();

    private final byte[] secretKey;
    private final byte[] ephemeralKeyPublic;

    /**
     * EciesEnvelopeKey constructor with secret key and ephemeral public key.
     *
     * @param secretKey Derived secret key.
     * @param ephemeralPublicKey Ephemeral public key.
     */
    public EciesEnvelopeKey(byte[] secretKey, byte[] ephemeralPublicKey) {
        this.secretKey = secretKey;
        this.ephemeralKeyPublic = ephemeralPublicKey;
    }

    /**
     * Construct envelope key for ECIES from public key.
     *
     * @param publicKey Public key for ECIES scheme.
     * @param sharedInfo1 Additional information added to sharedInfo1 parameter for KDF function.
     * @return ECIES envelope key.
     * @throws EciesException Thrown when key derivation fails.
     */
    static EciesEnvelopeKey fromPublicKey(PublicKey publicKey, byte[] sharedInfo1) throws EciesException {
        try {
            // Generate ephemeral key pair
            final KeyPair ephemeralKeyPair = keyGenerator.generateKeyPair();
            final PrivateKey ephemeralPrivateKey = ephemeralKeyPair.getPrivate();
            final PublicKey ephemeralPublicKey = ephemeralKeyPair.getPublic();

            // Convert ephemeral key to bytes
            final byte[] ephemeralPublicKeyBytes = keyConverter.convertPublicKeyToBytes(ephemeralPublicKey);

            // Compute ephemeral secret key using ECDH key agreement
            final SecretKey ephemeralSecretKey = keyGenerator.computeSharedKey(ephemeralPrivateKey, publicKey, true);

            // Construct final data for parameter sharedInfo1
            byte[] info1Data = sharedInfo1 == null ? ephemeralPublicKeyBytes : Bytes.concat(sharedInfo1, ephemeralPublicKeyBytes);

            // Derive secret key using KDF function
            byte[] secretKey = KdfX9_63.derive(keyConverter.convertSharedSecretKeyToBytes(ephemeralSecretKey), info1Data, ENVELOPE_KEY_SIZE);

            // Return envelope key with derived secret key and ephemeral public key bytes
            return new EciesEnvelopeKey(secretKey, ephemeralPublicKeyBytes);
        } catch (InvalidKeyException ex) {
            throw new EciesException("Key derivation failed");
        }
    }

    /**
     * Construct envelope key for ECIES from private key.
     *
     * @param ephemeralKeyPrivate Private key for ECIES scheme.
     * @param ephemeralPublicKeyBytes Ephemeral public key bytes.
     * @param sharedInfo1 Additional information added to sharedInfo1 parameter for KDF function.
     * @return ECIES envelope key.
     * @throws EciesException Thrown when key derivation fails.
     */
    static EciesEnvelopeKey fromPrivateKey(PrivateKey ephemeralKeyPrivate, byte[] ephemeralPublicKeyBytes, byte[] sharedInfo1) throws EciesException {
        try {
            // Convert public key bytes to public key
            final PublicKey ephemeralPublicKey = keyConverter.convertBytesToPublicKey(ephemeralPublicKeyBytes);

            // Compute ephemeral secret key using ECDH key agreement
            final SecretKey ephemeralSecretKey = keyGenerator.computeSharedKey(ephemeralKeyPrivate, ephemeralPublicKey, true);

            // Construct final data for parameter sharedInfo1
            byte[] info1Data = sharedInfo1 == null ? ephemeralPublicKeyBytes : Bytes.concat(sharedInfo1, ephemeralPublicKeyBytes);

            // Derive secret key using KDF function
            byte[] secretKey = KdfX9_63.derive(keyConverter.convertSharedSecretKeyToBytes(ephemeralSecretKey), info1Data, ENVELOPE_KEY_SIZE);

            // Return envelope key with derived secret key and ephemeral public key bytes
            return new EciesEnvelopeKey(secretKey, ephemeralPublicKeyBytes);
        } catch (InvalidKeyException | InvalidKeySpecException ex) {
            throw new EciesException("Key derivation failed");
        }
    }

    /**
     * Get secret key for encryption or decryption.
     *
     * @return Secret key for encryption or decryption.
     * @throws EciesException In case encryption key is not valid.
     */
    public byte[] getEncKey() throws EciesException {
        if (!isValid()) {
            throw new EciesException("Encryption key is not valid");
        }
        ByteBuffer byteBuffer = ByteBuffer.allocate(ENVELOPE_KEY_SIZE / 2);
        byteBuffer.put(secretKey, 0, ENVELOPE_KEY_SIZE / 2);
        return byteBuffer.array();
    }

    /**
     * Get key for HMAC calculation.
     *
     * @return Key for HMAC calculation.
     * @throws EciesException In case MAC key is not valid.
     */
    public byte[] getMacKey() throws EciesException {
        if (!isValid()) {
            throw new EciesException("MAC key is not valid");
        }
        ByteBuffer byteBuffer = ByteBuffer.allocate(ENVELOPE_KEY_SIZE / 2);
        byteBuffer.put(secretKey, ENVELOPE_KEY_SIZE / 2, ENVELOPE_KEY_SIZE / 2);
        return byteBuffer.array();
    }

    /**
     * Get the complete secret key for ECIES.
     * @return Secret key for ECIES.
     * @throws EciesException In case secret key is not valid.
     */
    public byte[] getSecretKey() throws EciesException {
        if (!isValid()) {
            throw new EciesException("Secret key is not valid");
        }
        return secretKey;
    }

    /**
     * Get ephemeral public key.
     *
     * @return Ephemeral public key.
     */
    public byte[] getEphemeralKeyPublic() {
        return ephemeralKeyPublic;
    }

    /**
     * Get whether derived secret key is valid.
     *
     * @return Whether derived secret key is valid.
     */
    public boolean isValid() {
        return secretKey.length == ENVELOPE_KEY_SIZE;
    }
}
