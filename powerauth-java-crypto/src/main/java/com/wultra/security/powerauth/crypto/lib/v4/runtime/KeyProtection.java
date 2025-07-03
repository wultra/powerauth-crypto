/*
 * PowerAuth Crypto Library
 * Copyright 2025 Wultra s.r.o.
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

package com.wultra.security.powerauth.crypto.lib.v4.runtime;

import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.AESEncryptionUtils;
import com.wultra.security.powerauth.crypto.lib.util.ByteUtils;
import com.wultra.security.powerauth.crypto.lib.util.KeyConvertor;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.Kdf;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.KeyFactory;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.KeyLabel;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;

/**
 * Wrap sensitive keys in memory using a simple AES-CTR encryption scheme.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class KeyProtection {

    private static final AESEncryptionUtils AES = new AESEncryptionUtils();
    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    private static final int KEK_LENGTH = 32;
    private static final int IV_LENGTH = 16;

    /**
     * Protect a key by wrapping it using encryption.
     *
     * @param key                 Secret key to wrap.
     * @param keyActivationSecret The {@code KEY_ACTIVATION_SECRET} key.
     * @param keyLabel            Key label representing the runtime protection context.
     * @return Wrapped key bytes, suitable for transport or temporary storage.
     * @throws GenericCryptoException  In case of encryption failure.
     * @throws CryptoProviderException In case that the cryptography provider is initialized incorrectly.
     * @throws InvalidKeyException     In case the key is invalid.
     */
    public static byte[] wrapKey(SecretKey key, SecretKey keyActivationSecret, KeyLabel keyLabel) throws GenericCryptoException, CryptoProviderException, InvalidKeyException {
        final KekIv kekIv = deriveKekAndIv(keyActivationSecret, keyLabel);
        final byte[] keyBytes = KEY_CONVERTOR.convertSharedSecretKeyToBytes(key);
        return AES.encrypt(keyBytes, kekIv.iv(), kekIv.kek(), "AES/CTR/NoPadding");
    }

    /**
     * Unwrap a protected key by decrypting it.
     *
     * @param wrappedKey          Wrapped key bytes.
     * @param keyActivationSecret The {@code KEY_ACTIVATION_SECRET} key.
     * @param keyLabel            KeyLabel representing the runtime protection context.
     * @return Unwrapped SecretKey.
     * @throws GenericCryptoException  In case of decryption failure.
     * @throws CryptoProviderException In case that the cryptography provider is initialized incorrectly.
     * @throws InvalidKeyException     In case the key is invalid.
     */
    public static SecretKey unwrapKey(byte[] wrappedKey, SecretKey keyActivationSecret, KeyLabel keyLabel) throws GenericCryptoException, CryptoProviderException, InvalidKeyException {
        final KekIv kekIv = deriveKekAndIv(keyActivationSecret, keyLabel);
        final byte[] keyBytes = AES.decrypt(wrappedKey, kekIv.iv(), kekIv.kek(), "AES/CTR/NoPadding");
        return KEY_CONVERTOR.convertBytesToSharedSecretKey(keyBytes);
    }

    /**
     * Record for KEK and IV.
     */
    private record KekIv(SecretKey kek, byte[] iv) {
    }

    /**
     * Derive KEK and IV from the activation secret key and label.
     *
     * @param keyActivationSecret The {@code KEY_ACTIVATION_SECRET} key.
     * @param keyLabel            KeyLabel representing the runtime protection context.
     * @return Derived KEK and IV.
     * @throws GenericCryptoException In case key derivation fails.
     */
    private static KekIv deriveKekAndIv(SecretKey keyActivationSecret, KeyLabel keyLabel) throws GenericCryptoException {
        final SecretKey kdkUtility = KeyFactory.deriveKdkUtility(keyActivationSecret);
        final SecretKey kekAndIv = Kdf.derive(kdkUtility, keyLabel.value(), null, KEK_LENGTH + IV_LENGTH);
        final byte[] kekAndIvBytes = KEY_CONVERTOR.convertSharedSecretKeyToBytes(kekAndIv);
        final SecretKey kek = KEY_CONVERTOR.convertBytesToSharedSecretKey(ByteUtils.subarray(kekAndIvBytes, 0, KEK_LENGTH));
        final byte[] iv = ByteUtils.subarray(kekAndIvBytes, KEK_LENGTH, IV_LENGTH);
        return new KekIv(kek, iv);
    }

}
