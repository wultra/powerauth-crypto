/*
 * PowerAuth Crypto Library
 * Copyright 2026 Wultra s.r.o.
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

package com.wultra.security.powerauth.crypto.lib.sdk;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Serializer for PowerAuth mobile SDK configuration.
 * Converts {@link SdkConfiguration} to and from a compact binary format
 * compatible with the PowerAuth mobile SDK.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class SdkConfigurationSerializer {

    private static final byte SDK_CONFIGURATION_VERSION = 0x01;
    private static final byte KEY_MASTER_ECDSA_P256_PUBLIC = 0x01;
    private static final byte KEY_MASTER_ECDSA_P384_PUBLIC = 0x02;
    private static final byte KEY_MASTER_MLDSA65_PUBLIC = 0x03;
    private static final byte KEY_MASTER_MLDSA87_PUBLIC = 0x04;

    /**
     * Serialize SDK configuration into a single Base-64 encoded string.
     * @param config SDK configuration.
     * @return Base-64 encoded string.
     * @throws SdkConfigurationException In case SDK configuration is invalid.
     */
    public static String serialize(final SdkConfiguration config) throws SdkConfigurationException {
        if (config == null) {
            throw new SdkConfigurationException("SDK configuration is null");
        }

        final String appKey = config.appKey();
        if (appKey == null || appKey.isEmpty()) {
            throw new SdkConfigurationException("Missing parameter appKey in SDK configuration");
        }
        
        final String appSecret = config.appSecret();
        if (appSecret == null || appSecret.isEmpty()) {
            throw new SdkConfigurationException("Missing parameter appSecret in SDK configuration");
        }

        final Map<Byte, String> publicKeys = new LinkedHashMap<>();
        final String publicKeyP256 = config.masterPublicKeyP256();
        if (publicKeyP256 != null) {
            publicKeys.put(KEY_MASTER_ECDSA_P256_PUBLIC, publicKeyP256);
        }

        final String publicKeyP384 = config.masterPublicKeyP384();
        if (publicKeyP384 != null) {
            publicKeys.put(KEY_MASTER_ECDSA_P384_PUBLIC, publicKeyP384);
        }

        final String publicKeyMlDsa65 = config.masterPublicKeyMlDsa65();
        if (publicKeyMlDsa65 != null) {
            publicKeys.put(KEY_MASTER_MLDSA65_PUBLIC, publicKeyMlDsa65);
        }

        final String publicKeyMlDsa87 = config.masterPublicKeyMlDsa87();
        if (publicKeyMlDsa87 != null) {
            publicKeys.put(KEY_MASTER_MLDSA87_PUBLIC, publicKeyMlDsa87);
        }

        final DataWriter writer = new DataWriter();
        writer.writeByte(SDK_CONFIGURATION_VERSION);
        writer.writeData(Base64.getDecoder().decode(appKey));
        writer.writeData(Base64.getDecoder().decode(appSecret));
        serializeKeys(writer, publicKeys);
        return Base64.getEncoder().encodeToString(writer.getSerializedData());
    }

    /**
     * Deserialize SDK configuration from a Base-64 encoded string.
     * @param serialized Serialized SDK configuration.
     * @return SDK configuration.
     * @throws SdkConfigurationException In case serialized SDK configuration is invalid.
     */
    public static SdkConfiguration deserialize(final String serialized) throws SdkConfigurationException {
        if (serialized == null || serialized.isEmpty()) {
            throw new SdkConfigurationException("Serialized SDK configuration is empty");
        }

        final byte[] serializedBytes = Base64.getDecoder().decode(serialized);
        final DataReader reader = new DataReader(serializedBytes);

        final Byte version = reader.readByte();
        if (version == null || version != SDK_CONFIGURATION_VERSION) {
            throw new SdkConfigurationException("Invalid SDK configuration version: " + version);
        }

        final byte[] appKey = reader.readData(16);
        if (appKey == null) {
            throw new SdkConfigurationException("Missing parameter appKey in SDK configuration");
        }

        final byte[] appSecret = reader.readData(16);
        if (appSecret == null) {
            throw new SdkConfigurationException("Missing parameter appSecret in SDK configuration");
        }

        final Map<Byte, String> publicKeys = deserializeKeys(reader);
        final String publicKeyP256 = publicKeys.get(KEY_MASTER_ECDSA_P256_PUBLIC);
        final String publicKeyP384 = publicKeys.get(KEY_MASTER_ECDSA_P384_PUBLIC);
        final String publicKeyMlDsa65 = publicKeys.get(KEY_MASTER_MLDSA65_PUBLIC);
        final String publicKeyMlDsa87 = publicKeys.get(KEY_MASTER_MLDSA87_PUBLIC);
        final String appKeyBase64 = Base64.getEncoder().encodeToString(appKey);
        final String appSecretBase64 = Base64.getEncoder().encodeToString(appSecret);
        return SdkConfiguration.builder()
                .appKey(appKeyBase64)
                .appSecret(appSecretBase64)
                .masterPublicKeyP256(publicKeyP256)
                .masterPublicKeyP384(publicKeyP384)
                .masterPublicKeyMlDsa65(publicKeyMlDsa65)
                .masterPublicKeyMlDsa87(publicKeyMlDsa87)
                .build();
    }

    /**
     * Serialize public keys using writer.
     * @param writer SDK data writer.
     * @param publicKeys Map of public key ID to public key in Base-64 format.
     */
    private static void serializeKeys(final DataWriter writer, final Map<Byte, String> publicKeys) {
        writer.writeCount(publicKeys.size());
        for (Map.Entry<Byte, String> key : publicKeys.entrySet()) {
            writer.writeByte(key.getKey());
            final byte[] publicKeyBytes = Base64.getDecoder().decode(key.getValue());
            writer.writeData(publicKeyBytes);
        }
    }

    /**
     * Deserialize public keys using reader.
     * @param reader SDK data reader.
     * @return Map of public key ID to public key in Base-64 format.
     */
    private static Map<Byte, String> deserializeKeys(final DataReader reader) throws SdkConfigurationException {
        final Integer keyCount = reader.readCount();
        if (keyCount == null) {
            throw new SdkConfigurationException("Missing key count in SDK configuration");
        }

        final Map<Byte, String> publicKeys = new LinkedHashMap<>();
        for (int i = 0; i < keyCount; i++) {
            final Byte keyId = reader.readByte();
            if (keyId == null) {
                throw new SdkConfigurationException("Missing key identifier in SDK configuration");
            }

            final byte[] publicKey = reader.readData(0);
            if (publicKey == null) {
                throw new SdkConfigurationException("Missing public key in SDK configuration");
            }
            publicKeys.put(keyId, Base64.getEncoder().encodeToString(publicKey));
        }

        return publicKeys;
    }

}
