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

/**
 * Enumeration of key labels used during key derivation.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public enum KeyLabel {

    /** Label for deriving {@code KDK_SIGNATURE} from {@code KEY_ACTIVATION_SECRET}. */
    AUTH("auth"),

    /** Label for deriving {@code KEY_SIGNATURE_POSSESSION} from {@code KDK_SIGNATURE}. */
    AUTH_POSSESSION("auth/possession"),

    /** Label for deriving {@code KEY_SIGNATURE_KNOWLEDGE} from {@code KDK_SIGNATURE}. */
    AUTH_KNOWLEDGE("auth/knowledge"),

    /** Label for deriving {@code KEY_SIGNATURE_BIOMETRY} from {@code KDK_SIGNATURE}. */
    AUTH_BIOMETRY("auth/biometry"),

    /** Label for deriving {@code KEY_SHARED_SECRET} from {@code KEY_SHARED_SECRET_ECDHE} (algorithm EC_P384). */
    SHARED_SECRET_EC_P384("shared-secret/ec-p384"),

    /** Label for deriving {@code KEY_SHARED_SECRET} from {@code KEY_SHARED_SECRET_HYBRID} (algorithm EC_P384_ML_L3). */
    SHARED_SECRET_EC_P384_ML_L3("shared-secret/ec-p384-ml-l3"),

    /** Label for deriving {@code KEY_ENC} from {@code BASE_KEY}. */
    AEAD_ENC("aead/enc"),

    /** Label for deriving {@code KEY_MAC} from {@code BASE_KEY}. */
    AEAD_MAC("aead/mac"),

    /** Label for deriving {@code KDK_VAULT} from {@code KEY_ACTIVATION_SECRET}. */
    VAULT("vault"),

    /** Label for deriving {@code KEK_DEVICE_PRIVATE} from {@code KDK_VAULT}. */
    VAULT_KEK_DEVICE_PRIVATE("vault/kek-device-private"),

    /** Label for deriving {@code KDK_APP_VAULT_KNOWLEDGE} from {@code KDK_VAULT}. */
    KDK_APP_VAULT_KNOWLEDGE("vault/kdk-app-vault-knowledge"),

    /** Label for deriving {@code KDK_APP_VAULT_2FA} from {@code KDK_VAULT}. */
    KDK_APP_VAULT_2FA("vault/kdk-app-vault-2fa"),

    /** Label for deriving {@code KDK_UTILITY} from {@code KEY_ACTIVATION_SECRET}. */
    UTIL("util"),

    /** Label for deriving {@code KEY_MAC_CTR_DATA} from {@code KDK_UTILITY}. */
    UTIL_MAC_CTR_DATA("util/mac/ctr-data"),

    /** Label for deriving {@code KEY_MAC_STATUS} from {@code KDK_UTILITY}. */
    UTIL_MAC_STATUS("util/mac/status"),

    /** Label for deriving {@code KEY_MAC_GET_APP_TEMP_KEY} from {@code APP_SECRET}. */
    UTIL_MAC_GET_APP_TEMP_KEY("util/mac/get-app-temp-key"),

    /** Label for deriving {@code KEY_MAC_GET_ACT_TEMP_KEY} from {@code KDK_UTILITY}. */
    UTIL_MAC_GET_ACT_TEMP_KEY("util/mac/get-act-temp-key"),

    /** Label for deriving {@code KEY_MAC_PERSONALIZED_DATA} from {@code KDK_UTILITY}. */
    UTIL_MAC_PERSONALIZED_DATA("util/mac/personalized-data"),

    /** Label for deriving {@code KEY_E2EE_SHARED_INFO2} from {@code KDK_UTILITY}. */
    UTIL_KEY_E2EE_SH2("util/key-e2ee-sh2");

    private final String label;

    /**
     * Key label enumeration constructor.
     * @param label Key label.
     */
    KeyLabel(String label) {
        this.label = label;
    }

    /**
     * Get the key label.
     * @return Key label.
     */
    public String value() {
        return label;
    }

    @Override
    public String toString() {
        return label;
    }
}
