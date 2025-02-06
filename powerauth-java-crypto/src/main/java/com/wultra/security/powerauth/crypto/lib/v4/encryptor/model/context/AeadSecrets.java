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

package com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.context;

import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorSecrets;
import lombok.*;

/**
 * The {@code AeadSecrets} class provides secret values for encryptor using V4 scheme.
 * <p>PowerAuth protocol versions:
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Getter
@Data
@ToString(onlyExplicitlyIncluded = true)
public class AeadSecrets implements EncryptorSecrets {

    /**
     * Precalculated envelope key.
     */
    private final byte[] envelopeKey;

    /**
     * Application secret.
     */
    private final String applicationSecret;

    /**
     * SharedInfo2 key, required for activation scoped encryptor.
     */
    private final byte[] keySharedInfo2;

    /**
     * Precalculated SharedInfo2. If provided, then {@link #applicationSecret} or {@link #keySharedInfo2} is not
     * required.
     */
    private final byte[] sharedInfo2;

    /**
     * Construct encryptor secrets for an application scoped encryptor. In this variant, the SharedInfo2 is not known
     * in advance and will be calculated in the encryptor.
     * @param envelopeKey Pre-shared envelope key.
     * @param applicationSecret Application's secret string.
     */
    public AeadSecrets(byte[] envelopeKey, String applicationSecret) {
        this.envelopeKey = envelopeKey;
        this.applicationSecret = applicationSecret;
        this.keySharedInfo2 = null;
        this.sharedInfo2 = null;
    }

    /**
     * Construct encryptor secrets for an activation scoped encryptor. In this variant, the SharedInfo2 is not known
     * in advance and will be calculated in the encryptor.
     * @param envelopeKey Pre-shared envelope key.
     * @param applicationSecret Application's secret string.
     * @param keySharedInfo2 SharedInfo2 encryption key. The value is required for activation scoped encryptor. If null is provided,
     *                     then such secrets can be used for application scoped encryptor only.
     */
    public AeadSecrets(byte[] envelopeKey, String applicationSecret, byte[] keySharedInfo2) {
        this.envelopeKey = envelopeKey;
        this.applicationSecret = applicationSecret;
        this.keySharedInfo2 = keySharedInfo2;
        this.sharedInfo2 = null;
    }

    /**
     * Construct encryptor secrets with precalculated SharedInfo2. This type of configuration is useful in case
     * that SharedInfo2 is known in advance.
     * @param envelopeKey Pre-shared envelope key.
     * @param sharedInfo2 Precalculated SharedInfo2.
     */
    public AeadSecrets(byte[] envelopeKey, byte[] sharedInfo2) {
        this.envelopeKey = envelopeKey;
        this.applicationSecret = null;
        this.keySharedInfo2 = null;
        this.sharedInfo2 = sharedInfo2;
    }

}
