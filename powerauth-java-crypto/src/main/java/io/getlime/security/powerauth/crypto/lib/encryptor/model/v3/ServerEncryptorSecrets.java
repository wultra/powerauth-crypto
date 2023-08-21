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

import java.security.PrivateKey;

/**
 * The {@code ServerEncryptorSecrets} class provides secret values for server side encryptor using ECIES scheme.
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
public class ServerEncryptorSecrets implements EncryptorSecrets {
    /**
     * Server's private key.
     */
    private final PrivateKey serverPrivateKey;
    /**
     * Application's secret.
     */
    private final String applicationSecret;
    /**
     * Transport key, required for activation scoped encryptor.
     */
    private final byte[] transportKey;
    /**
     * Precalculated envelope key.
     */
    private final byte[] envelopeKey;
    /**
     * Precalculated SharedInfo2 base.
     */
    private final byte[] sharedInfo2Base;

    /**
     * Construct encryptor secrets for an activation scoped encryptor. In this variant, the SharedInfo2 base is not
     * known in advance and will be calculated in the encryptor.
     * @param serverPrivateKey Server's private key.
     * @param applicationSecret Application's secret.
     * @param transportKey Transport key. The value is required for activation scoped encryptor. If null is provided,
     *                     then such secrets can be used for application scoped encryptor only.
     */
    public ServerEncryptorSecrets(PrivateKey serverPrivateKey, String applicationSecret, byte[] transportKey) {
        this.serverPrivateKey = serverPrivateKey;
        this.envelopeKey = null;
        this.transportKey = transportKey;
        this.sharedInfo2Base = null;
        this.applicationSecret = applicationSecret;
    }

    /**
     * Construct encryptor secrets for an application scoped encryptor. In this variant, the SharedInfo2 base is not
     * known in advance and will be calculated in the encryptor.
     * @param serverPrivateKey Server's private key.
     * @param applicationSecret Application's secret.
     */
    public ServerEncryptorSecrets(PrivateKey serverPrivateKey, String applicationSecret) {
        this.serverPrivateKey = serverPrivateKey;
        this.envelopeKey = null;
        this.transportKey = null;
        this.sharedInfo2Base = null;
        this.applicationSecret = applicationSecret;
    }

    /**
     * Construct encryptor secrets with precalculated envelope key and SharedInfo2 base. This type of configuration
     * is useful for situations when such values are obtained from elsewhere. For example, our RESTful integration
     * library doesn't know server's private key, but can get such precomputed secrets from the PowerAuth Server.
     *
     * @param envelopeKey Precalculated envelope key.
     * @param sharedInfo2Base Precalculated SharedInfo2 base.
     */
    public ServerEncryptorSecrets(byte[] envelopeKey, byte[] sharedInfo2Base) {
        this.serverPrivateKey = null;
        this.envelopeKey = envelopeKey;
        this.transportKey = null;
        this.sharedInfo2Base = sharedInfo2Base;
        this.applicationSecret = null;
    }
}

