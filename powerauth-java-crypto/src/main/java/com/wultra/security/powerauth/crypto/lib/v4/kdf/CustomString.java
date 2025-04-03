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
 * Enumeration of custom strings used during key derivation.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public enum CustomString {

    /**
     * Key derivation using label.
     */
    PA4KDF("PA4KDF"),

    /**
     * Key derivation using password.
     */
    PA4PBKDF("PA4PBKDF"),

    /**
     * Key derivation for authentication codes.
     */
    PA4CODE("PA4CODE"),

    /**
     * Key derivation for MAC tokens.
     */
    PA4DIGEST("PA4DIGEST"),

    /**
     * Key derivation for data digests.
     */
    PA4DIGEST_DATA("PA4DIGEST-DATA"),

    /**
     * Key derivation for sharedInfo2 parameter.
     */
    PA4SH2("PA4SH2"),

    /**
     * Key derivation for MAC in AEAD.
     */
    PA4MAC_AEAD("PA4MAC-AEAD");

    private final String customString;

    /**
     * Custom string enumeration constructor.
     * @param customString Custom string value.
     */
    CustomString(String customString) {
        this.customString = customString;
    }

    /**
     * Get the custom string.
     * @return Custom string.
     */
    public String value() {
        return customString;
    }

    @Override
    public String toString() {
        return customString;
    }

}
