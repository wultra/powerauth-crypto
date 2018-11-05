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
package io.getlime.security.powerauth.crypto.server.vault;

import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthDerivedKey;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.provider.CryptoProviderUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Class implementing server-side logic for PowerAuth vault encryption.
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthServerVault {

    /**
     * Return encrypted vault encryption key KEY_ENCRYPTION_VAULT using
     * a correct KEY_ENCRYPTION_VAULT_TRANSPORT.
     *
     * <h5>PowerAuth protocol versions:</h5>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     * @param serverPrivateKey Server private key KEY_SERVER_PRIVATE
     * @param devicePublicKey Device public key KEY_DEVICE_PUBLIC
     * @param ctr Counter data.
     * @return Encrypted vault encryption key.
     * @throws InvalidKeyException In case a provided key is incorrect.
     * @throws GenericCryptoException In case encryption fails.
     */
    public byte[] encryptVaultEncryptionKey(PrivateKey serverPrivateKey, PublicKey devicePublicKey, byte[] ctr) throws InvalidKeyException, GenericCryptoException {
        try {
            KeyGenerator keyGenerator = new KeyGenerator();
            SecretKey keyMasterSecret = keyGenerator.computeSharedKey(serverPrivateKey, devicePublicKey);
            SecretKey keyMasterTransport = keyGenerator.deriveSecretKey(keyMasterSecret, PowerAuthDerivedKey.TRANSPORT.getIndex());
            SecretKey keyVaultEncryptionTransport = keyGenerator.deriveSecretKey(keyMasterTransport, ctr);
            SecretKey keyVaultEncryption = keyGenerator.deriveSecretKey(keyMasterSecret, PowerAuthDerivedKey.ENCRYPTED_VAULT.getIndex());

            CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
            byte[] keyVaultEncryptionBytes = keyConvertor.convertSharedSecretKeyToBytes(keyVaultEncryption);
            byte[] iv = new byte[16];
            AESEncryptionUtils aes = new AESEncryptionUtils();
            return aes.encrypt(keyVaultEncryptionBytes, iv, keyVaultEncryptionTransport);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

    /**
     * Return encrypted vault encryption key KEY_ENCRYPTION_VAULT using KEY_TRANSPORT.
     *
     * <h5>PowerAuth protocol versions:</h5>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @param serverPrivateKey Server private key KEY_SERVER_PRIVATE
     * @param devicePublicKey Device public key KEY_DEVICE_PUBLIC
     * @return Encrypted vault encryption key.
     * @throws InvalidKeyException In case a provided key is incorrect.
     * @throws GenericCryptoException In case encryption fails.
     */
    public byte[] encryptVaultEncryptionKey(PrivateKey serverPrivateKey, PublicKey devicePublicKey) throws InvalidKeyException, GenericCryptoException {
        try {
            KeyGenerator keyGenerator = new KeyGenerator();
            SecretKey keyMasterSecret = keyGenerator.computeSharedKey(serverPrivateKey, devicePublicKey);
            SecretKey keyTransport = keyGenerator.deriveSecretKey(keyMasterSecret, PowerAuthDerivedKey.TRANSPORT.getIndex());
            SecretKey keyVaultEncryption = keyGenerator.deriveSecretKey(keyMasterSecret, PowerAuthDerivedKey.ENCRYPTED_VAULT.getIndex());

            CryptoProviderUtil keyConvertor = PowerAuthConfiguration.INSTANCE.getKeyConvertor();
            byte[] keyVaultEncryptionBytes = keyConvertor.convertSharedSecretKeyToBytes(keyVaultEncryption);
            byte[] iv = new byte[16];
            AESEncryptionUtils aes = new AESEncryptionUtils();
            return aes.encrypt(keyVaultEncryptionBytes, iv, keyTransport);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            throw new GenericCryptoException(ex.getMessage(), ex);
        }
    }

}
