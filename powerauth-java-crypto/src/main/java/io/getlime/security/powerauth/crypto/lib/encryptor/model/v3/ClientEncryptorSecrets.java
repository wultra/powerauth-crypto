/*
 * PowerAuth Crypto Library
 * Copyright 2023 Wultra s.r.o.
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

package io.getlime.security.powerauth.crypto.lib.encryptor.model.v3;

import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorSecrets;
import lombok.Data;
import lombok.Getter;
import lombok.ToString;

import java.security.PublicKey;

/**
 * The {@code ClientEncryptorSecrets} class provides secret values for client side encryptor using ECIES scheme.
 * <p>PowerAuth protocol versions:
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 * </ul>
 */
@Getter
@Data
@ToString(onlyExplicitlyIncluded = true)
public class ClientEncryptorSecrets implements EncryptorSecrets {
    /**
     * Server's public key.
     */
    private final PublicKey serverPublicKey;
    /**
     * Application secret.
     */
    private final String applicationSecret;
    /**
     * Transport key, required for activation scoped encryptor.
     */
    private final byte[] transportKey;
    /**
     * Precalculated SharedInfo2 base. If provided, then {@link #applicationSecret} or {@link #transportKey} is not
     * required.
     */
    private final byte[] sharedInfo2Base;

    /**
     * Construct encryptor secrets for an application scoped encryptor. In this variant, the SharedInfo2 base is not known
     * in advance and will be calculated in the encryptor.
     * @param serverPublicKey Server's public key.
     * @param applicationSecret Application's secret string.
     */
    public ClientEncryptorSecrets(PublicKey serverPublicKey, String applicationSecret) {
        this.serverPublicKey = serverPublicKey;
        this.applicationSecret= applicationSecret;
        this.transportKey = null;
        this.sharedInfo2Base = null;
    }

    /**
     * Construct encryptor secrets for an activation scoped encryptor. In this variant, the SharedInfo2 base is not known
     * in advance and will be calculated in the encryptor.
     * @param serverPublicKey Server's public key.
     * @param applicationSecret Application's secret string.
     * @param transportKey Transport key. The value is required for activation scoped encryptor. If null is provided,
     *                     then such secrets can be used for application scoped encryptor only.
     */
    public ClientEncryptorSecrets(PublicKey serverPublicKey, String applicationSecret, byte[] transportKey) {
        this.serverPublicKey = serverPublicKey;
        this.applicationSecret = applicationSecret;
        this.transportKey = transportKey;
        this.sharedInfo2Base = null;
    }

    /**
     * Construct encryptor secrets with precalculated SharedInfo2 base. This type of configuration is useful in case
     * that SharedInfo2 base is known in advance.
     * @param serverPublicKey Server's public key.
     * @param sharedInfo2Base Precalculated SharedInfo2 base.
     */
    public ClientEncryptorSecrets(PublicKey serverPublicKey, byte[] sharedInfo2Base) {
        this.serverPublicKey = serverPublicKey;
        this.applicationSecret = null;
        this.transportKey = null;
        this.sharedInfo2Base = sharedInfo2Base;
    }


}
