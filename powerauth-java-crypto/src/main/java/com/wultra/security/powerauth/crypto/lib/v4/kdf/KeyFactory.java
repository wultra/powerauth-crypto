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

package com.wultra.security.powerauth.crypto.lib.v4.kdf;

import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;

import javax.crypto.SecretKey;

/**
 * KeyFactory is a utility class for deriving keys from provided source keys using the KMAC-based KDF function.
 * Key are derived using specific derivation paths, as defined in the V4 key index registry.
 * The default key length is 32 bytes and it is used for all the derived keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class KeyFactory {

    /**
     * Derives {@code KEY_SIGNATURE_POSSESSION} from {@code KEY_ACTIVATION_SECRET}.
     *
     * @param keyActivationSecret The activation secret key.
     * @return Derived possession factor key.
     * @throws GenericCryptoException In case of cryptographic failure.
     */
    public static SecretKey deriveKeySignaturePossession(SecretKey keyActivationSecret) throws GenericCryptoException {
        SecretKey kdkSignature = deriveKdkSignature(keyActivationSecret);
        return deriveKeySignaturePossessionFromKdk(kdkSignature);
    }

    /**
     * Derives {@code KEY_SIGNATURE_KNOWLEDGE} from {@code KEY_ACTIVATION_SECRET}.
     *
     * @param keyActivationSecret The activation secret key.
     * @return Derived knowledge factor key.
     * @throws GenericCryptoException In case of cryptographic failure.
     */
    public static SecretKey deriveKeySignatureKnowledge(SecretKey keyActivationSecret) throws GenericCryptoException {
        SecretKey kdkSignature = deriveKdkSignature(keyActivationSecret);
        return deriveKeySignatureKnowledgeFromKdk(kdkSignature);
    }

    /**
     * Derives {@code KEY_SIGNATURE_BIOMETRY} from {@code KEY_ACTIVATION_SECRET}.
     *
     * @param keyActivationSecret The activation secret key.
     * @return Derived biometry factor key.
     * @throws GenericCryptoException In case of cryptographic failure.
     */
    public static SecretKey deriveKeySignatureBiometry(SecretKey keyActivationSecret) throws GenericCryptoException {
        SecretKey kdkSignature = deriveKdkSignature(keyActivationSecret);
        return deriveKeySignatureBiometryFromKdk(kdkSignature);
    }

    /**
     * Derives {@code KEY_SHARED_SECRET} from {@code KEY_SHARED_SECRET_ECDHE} (algorithm EC_P384).
     *
     * @param keySharedSecretEcdhe Shared secret from ECDHE key exchange.
     * @return Derived shared secret key.
     * @throws GenericCryptoException In case of cryptographic failure.
     */
    public static SecretKey deriveKeySharedSecretEcdhe(SecretKey keySharedSecretEcdhe) throws GenericCryptoException {
        return derive(keySharedSecretEcdhe, KeyLabel.SHARED_SECRET_EC_P384);
    }

    /**
     * Derives {@code KEY_SHARED_SECRET3} from {@code KEY_SHARED_SECRET_HYBRID} (algorithm EC_P384_ML_L3).
     *
     * @param keySharedSecretHybrid Shared secret from hybrid key exchange.
     * @return Derived hybrid shared secret key.
     * @throws GenericCryptoException In case of cryptographic failure.
     */
    public static SecretKey deriveKeySharedSecretHybrid(SecretKey keySharedSecretHybrid) throws GenericCryptoException {
        return derive(keySharedSecretHybrid, KeyLabel.SHARED_SECRET_EC_P384_ML_L3);
    }

    /**
     * Derives {@code KEY_ENC} from {@code BASE_KEY}.
     *
     * @param keyBase     Base key for AEAD encryption.
     * @param diversifier Diversifier for additional key separation.
     * @return Derived AEAD encryption key.
     * @throws GenericCryptoException In case of cryptographic failure.
     */
    public static SecretKey deriveKeyAeadEnc(SecretKey keyBase, byte[] diversifier) throws GenericCryptoException {
        return derive(keyBase, KeyLabel.AEAD_ENC, diversifier);
    }

    /**
     * Derives {@code KEY_MAC} from {@code BASE_KEY}.
     *
     * @param keyBase     Base key for AEAD MAC.
     * @param diversifier Diversifier for additional key separation.
     * @return Derived AEAD MAC key.
     * @throws GenericCryptoException In case of cryptographic failure.
     */
    public static SecretKey deriveKeyAeadMac(SecretKey keyBase, byte[] diversifier) throws GenericCryptoException {
        return derive(keyBase, KeyLabel.AEAD_MAC, diversifier);
    }

    /**
     * Derives {@code VAULT_KEK_DEVICE_PRIVATE} from {@code KEY_ACTIVATION_SECRET}.
     *
     * @param keyActivationSecret The activation secret key.
     * @return Derived KEK that encrypts {@code KEY_DEVICE_PRIVATE}.
     * @throws GenericCryptoException In case of cryptographic failure.
     */
    public static SecretKey deriveKeyKekDevicePrivate(SecretKey keyActivationSecret) throws GenericCryptoException {
        SecretKey kdkVault = deriveKdkVault(keyActivationSecret);
        return deriveKekDevicePrivateFromKdk(kdkVault);
    }

    /**
     * Derives {@code KDK_APP_VAULT_KNOWLEDGE} from {@code KEY_ACTIVATION_SECRET}.
     *
     * @param keyActivationSecret The activation secret key.
     * @return Derived vault KDK for knowledge-based 2FA authorization.
     * @throws GenericCryptoException In case of cryptographic failure.
     */
    public static SecretKey deriveKeyKdkAppVaultKnowledge(SecretKey keyActivationSecret) throws GenericCryptoException {
        SecretKey kdkVault = deriveKdkVault(keyActivationSecret);
        return deriveKeyKdkAppVaultKnowledgeFromKdk(kdkVault);
    }

    /**
     * Derives {@code KDK_APP_VAULT_2FA} from {@code KEY_ACTIVATION_SECRET}.
     *
     * @param keyActivationSecret The activation secret key.
     * @return Derived vault KDK for general 2FA authorization.
     * @throws GenericCryptoException In case of cryptographic failure.
     */
    public static SecretKey deriveKeyKdkAppVault2fa(SecretKey keyActivationSecret) throws GenericCryptoException {
        SecretKey kdkVault = deriveKdkVault(keyActivationSecret);
        return deriveKeyKdkAppVault2faFromKdk(kdkVault);
    }

    /**
     * Derives {@code KEY_MAC_CTR_DATA} from {@code KEY_ACTIVATION_SECRET}.
     *
     * @param keyActivationSecret The activation secret key.
     * @return Derived MAC key for counter data.
     * @throws GenericCryptoException In case of cryptographic failure.
     */
    public static SecretKey deriveKeyMacCtrData(SecretKey keyActivationSecret) throws GenericCryptoException {
        SecretKey kdkUtility = deriveKdkUtility(keyActivationSecret);
        return deriveKeyMacCtrDataFromKdk(kdkUtility);
    }

    /**
     * Derives {@code KEY_MAC_STATUS} from {@code KEY_ACTIVATION_SECRET}.
     *
     * @param keyActivationSecret The activation secret key.
     * @return Derived MAC key for activation status.
     * @throws GenericCryptoException In case of cryptographic failure.
     */
    public static SecretKey deriveKeyMacStatus(SecretKey keyActivationSecret) throws GenericCryptoException {
        SecretKey kdkUtility = deriveKdkUtility(keyActivationSecret);
        return deriveKeyMacStatusFromKdk(kdkUtility);
    }

    /**
     * Derives {@code KEY_MAC_GET_APP_TEMP_KEY} from {@code APP_SECRET}.
     *
     * @param keyAppSecret Application secret.
     * @return Derived MAC key for application-scoped temporary key.
     * @throws GenericCryptoException In case of cryptographic failure.
     */
    public static SecretKey deriveKeyMacGetAppTempKey(SecretKey keyAppSecret) throws GenericCryptoException {
        return derive(keyAppSecret, KeyLabel.UTIL_MAC_GET_APP_TEMP_KEY);
    }

    /**
     * Derives {@code KEY_MAC_GET_ACT_TEMP_KEY} from {@code KEY_ACTIVATION_SECRET}.
     *
     * @param keyActivationSecret The activation secret key.
     * @return Derived MAC key for activation-scoped temporary key.
     * @throws GenericCryptoException In case of cryptographic failure.
     */
    public static SecretKey deriveKeyMacGetActTempKey(SecretKey keyActivationSecret) throws GenericCryptoException {
        SecretKey kdkUtility = deriveKdkUtility(keyActivationSecret);
        return deriveKeyMacGetActTempKeyFromKdk(kdkUtility);
    }

    /**
     * Derives {@code KEY_E2EE_SHARED_INFO2} from {@code KEY_ACTIVATION_SECRET}.
     *
     * @param keyActivationSecret The activation secret key.
     * @return Derived E2EE SHARED_INFO_2 key.
     * @throws GenericCryptoException In case of cryptographic failure.
     */
    public static SecretKey deriveKeyE2eeSharedInfo2(SecretKey keyActivationSecret) throws GenericCryptoException {
        SecretKey kdkUtility = deriveKdkUtility(keyActivationSecret);
        return deriveKeyE2eeSharedInfo2FromKdk(kdkUtility);
    }

    /**
     * Derives {@code KDK_SIGNATURE} from {@code KEY_ACTIVATION_SECRET}.
     */
    private static SecretKey deriveKdkSignature(SecretKey keyActivationSecret) throws GenericCryptoException {
        return derive(keyActivationSecret, KeyLabel.AUTH);
    }

    /**
     * Derives {@code KEY_SIGNATURE_POSSESSION} from {@code KDK_SIGNATURE}.
     */
    private static SecretKey deriveKeySignaturePossessionFromKdk(SecretKey kdkSignature) throws GenericCryptoException {
        return derive(kdkSignature, KeyLabel.AUTH_POSSESSION);
    }

    /**
     * Derives {@code KEY_SIGNATURE_KNOWLEDGE} from {@code KDK_SIGNATURE}.
     */
    private static SecretKey deriveKeySignatureKnowledgeFromKdk(SecretKey kdkSignature) throws GenericCryptoException {
        return derive(kdkSignature, KeyLabel.AUTH_KNOWLEDGE);
    }

    /**
     * Derives {@code KEY_SIGNATURE_BIOMETRY} from {@code KDK_SIGNATURE}.
     */
    private static SecretKey deriveKeySignatureBiometryFromKdk(SecretKey kdkSignature) throws GenericCryptoException {
        return derive(kdkSignature, KeyLabel.AUTH_BIOMETRY);
    }

    /**
     * Derives {@code KDK_VAULT} from {@code KEY_ACTIVATION_SECRET}.
     */
    private static SecretKey deriveKdkVault(SecretKey keyActivationSecret) throws GenericCryptoException {
        return derive(keyActivationSecret, KeyLabel.VAULT);
    }

    /**
     * Derives {@code KEK_DEVICE_PRIVATE} from {@code KDK_VAULT}.
     */
    private static SecretKey deriveKekDevicePrivateFromKdk(SecretKey kdkVault) throws GenericCryptoException {
        return derive(kdkVault, KeyLabel.VAULT_KEK_DEVICE_PRIVATE);
    }

    /**
     * Derives {@code KDK_APP_VAULT_KNOWLEDGE} from {@code KDK_VAULT}.
     */
    private static SecretKey deriveKeyKdkAppVaultKnowledgeFromKdk(SecretKey kdkVault) throws GenericCryptoException {
        return derive(kdkVault, KeyLabel.KDK_APP_VAULT_KNOWLEDGE);
    }

    /**
     * Derives {@code KDK_APP_VAULT_2FA} from {@code KDK_VAULT}.
     */
    private static SecretKey deriveKeyKdkAppVault2faFromKdk(SecretKey kdkVault) throws GenericCryptoException {
        return derive(kdkVault, KeyLabel.KDK_APP_VAULT_2FA);
    }

    /**
     * Derives {@code KDK_UTILITY} from {@code KEY_ACTIVATION_SECRET}.
     */
    private static SecretKey deriveKdkUtility(SecretKey keyActivationSecret) throws GenericCryptoException {
        return derive(keyActivationSecret, KeyLabel.UTIL);
    }

    /**
     * Derives {@code KEY_MAC_CTR_DATA} from {@code KDK_UTILITY}.
     */
    private static SecretKey deriveKeyMacCtrDataFromKdk(SecretKey kdkUtility) throws GenericCryptoException {
        return derive(kdkUtility, KeyLabel.UTIL_MAC_CTR_DATA);
    }

    /**
     * Derives {@code KEY_MAC_STATUS} from {@code KDK_UTILITY}.
     */
    private static SecretKey deriveKeyMacStatusFromKdk(SecretKey kdkUtility) throws GenericCryptoException {
        return derive(kdkUtility, KeyLabel.UTIL_MAC_STATUS);
    }

    /**
     * Derives {@code KEY_MAC_GET_ACT_TEMP_KEY} from {@code KDK_UTILITY}.
     */
    private static SecretKey deriveKeyMacGetActTempKeyFromKdk(SecretKey kdkUtility) throws GenericCryptoException {
        return derive(kdkUtility, KeyLabel.UTIL_MAC_GET_ACT_TEMP_KEY);
    }

    /**
     * Derives {@code KEY_E2EE_SHARED_INFO2} from {@code KDK_UTILITY}.
     */
    private static SecretKey deriveKeyE2eeSharedInfo2FromKdk(SecretKey kdkUtility) throws GenericCryptoException {
        return derive(kdkUtility, KeyLabel.UTIL_KEY_E2EE_SH2);
    }

    /**
     * Derive a key using KDF with no diversifier and default length of 32 bytes.
     *
     * @param sourceKey Secret key used as input for the derivation.
     * @param label     Label used to uniquely identify the derived key purpose.
     * @return Derived secret key.
     * @throws GenericCryptoException Thrown in case of any cryptographic error.
     */
    private static SecretKey derive(SecretKey sourceKey, KeyLabel label) throws GenericCryptoException {
        return Kdf.derive(sourceKey, label.value(), null, 32);
    }

    /**
     * Derive a key using KDF with diversifier and default length of 32 bytes.
     *
     * @param sourceKey   Secret key used as input for the derivation.
     * @param label       Label used to uniquely identify the derived key purpose.
     * @param diversifier Diversifier bytes.
     * @return Derived secret key.
     * @throws GenericCryptoException Thrown in case of any cryptographic error.
     */
    private static SecretKey derive(SecretKey sourceKey, KeyLabel label, byte[] diversifier) throws GenericCryptoException {
        return Kdf.derive(sourceKey, label.value(), diversifier, 32);
    }

}
