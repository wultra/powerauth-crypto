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

package io.getlime.security.powerauth.crypto.lib.encryptor.model;

import io.getlime.security.powerauth.crypto.lib.util.ByteUtils;

import java.nio.charset.StandardCharsets;

/**
 * Enumeration with constants for parameter sharedInfo1.
 */
public enum EncryptorId {

    /**
     * Generic application encryption.
     */
    APPLICATION_SCOPE_GENERIC("/pa/generic/application", EncryptorScope.APPLICATION_SCOPE),

    /**
     * Generic activation encryption.
     */
    ACTIVATION_SCOPE_GENERIC("/pa/generic/activation", EncryptorScope.ACTIVATION_SCOPE),

    /**
     * Activation layer 2 encryption.
     */
    ACTIVATION_LAYER_2("/pa/activation", EncryptorScope.APPLICATION_SCOPE),

    /**
     * Upgrade protocol encryption.
     */
    UPGRADE("/pa/upgrade", EncryptorScope.ACTIVATION_SCOPE),

    /**
     * Vault unlock encryption.
     */
    VAULT_UNLOCK("/pa/vault/unlock", EncryptorScope.ACTIVATION_SCOPE),

    /**
     * Create token encryption.
     */
    CREATE_TOKEN("/pa/token/create", EncryptorScope.ACTIVATION_SCOPE),

    /**
     * Recovery code confirmation encryption.
     */
    CONFIRM_RECOVERY_CODE("/pa/recovery/confirm", EncryptorScope.ACTIVATION_SCOPE);

    private final String value;
    private final EncryptorScope scope;

    /**
     * Constructor with encryptor's identifier.
     * @param identifier Encryptor's identifier.
     * @param scope Encryptor's scope;
     */
    EncryptorId(String identifier, EncryptorScope scope) {
        this.value = identifier;
        this.scope = scope;
    }

    /**
     * Get identifier's value.
     * @return String with encryptor's identifier.
     */
    public String value() {
        return value;
    }

    /**
     * Get encryptor's scope;
     * @return Encryptor's scope;
     */
    public EncryptorScope scope() {
        return scope;
    }

    /**
     * Get bytes of sharedInfo1 parameter for ECIES scheme.
     * @param protocolVersion Version of protocol.
     * @return Bytes of sharedInfo1 parameter for ECIES scheme.
     */
    public byte[] getEciesSharedInfo1(String protocolVersion) {
        final byte[] valueBytes = value.getBytes(StandardCharsets.UTF_8);
        // 3.0, 3.1 or if version is unspecified, return value bytes
        if (protocolVersion == null || "3.0".equals(protocolVersion) || "3.1".equals(protocolVersion)) {
            return valueBytes;
        }
        // 3.2+ use protocol version as prefix to value
        return ByteUtils.concat(protocolVersion.getBytes(StandardCharsets.UTF_8), valueBytes);
    }
}
