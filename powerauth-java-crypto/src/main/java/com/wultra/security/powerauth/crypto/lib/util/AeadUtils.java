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
package com.wultra.security.powerauth.crypto.lib.util;

import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.exception.AeadException;
import com.wultra.security.powerauth.crypto.lib.v4.hash.Sha3;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.Kmac;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * A utility class for handling AEAD data.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public final class AeadUtils {

    private static final byte[] CRYPTO4_SH2_CUSTOM_BYTES = "PA4SH2".getBytes(StandardCharsets.UTF_8);

    private static final KeyConvertor KEY_CONVERTOR = new KeyConvertor();

    /**
     * Private constructor.
     */
    private AeadUtils() {
    }

    /**
     * Derive associated data for V4 end-to-end encryption scheme.
     * @param scope Encryptor's scope.
     * @param protocolVersion Protocol version.
     * @param applicationKey Application key.
     * @param activationId Activation ID.
     * @param temporaryKeyId Temporary key ID.
     * @return Derived associated data.
     * @throws AeadException In case of missing parameters.
     */
    public static byte[] deriveAssociatedData(EncryptorScope scope, String protocolVersion, String applicationKey, String activationId, String temporaryKeyId) throws AeadException {
        if (protocolVersion == null) {
            throw new AeadException("Protocol version is missing");
        }
        switch (protocolVersion) {
            case "4.0": {
                if (applicationKey == null) {
                    throw new AeadException("Application key is missing");
                }
                if (temporaryKeyId == null) {
                    throw new AeadException("Missing temporary key identifier");
                }
                if (scope == EncryptorScope.ACTIVATION_SCOPE) {
                    if (activationId == null) {
                        throw new AeadException("Activation ID is missing in ACTIVATION_SCOPE");
                    }
                    return ByteUtils.concatStrings(protocolVersion, applicationKey, activationId, temporaryKeyId);
                } else {
                    return ByteUtils.concatStrings(protocolVersion, applicationKey, temporaryKeyId);
                }
            }
            default: {
                return null;
            }
        }
    }

    /**
     * Derive base for SharedInfo2 calculation for V4 end-to-end encryption scheme.
     * @param scope Scope of the encryptor.
     * @param applicationSecret Application's secret.
     * @param keySharedInfo2 Key for deriving sharedInfo2.
     * @return Bytes representing SharedInfo2 base.
     * @throws AeadException In case of some required parameter is missing or if underlying cryptographic primitive fails.
     */
    public static byte[] deriveSharedInfo2(EncryptorScope scope, String applicationSecret, byte[] keySharedInfo2) throws AeadException {
        if (applicationSecret == null) {
            throw new AeadException("Missing applicationSecret parameter");
        }
        final byte[] applicationSecretBytes = applicationSecret.getBytes(StandardCharsets.UTF_8);
        if (scope == EncryptorScope.APPLICATION_SCOPE) {
            // Application scope
            return Sha3.hash256(applicationSecretBytes);
        } else {
            // Activation scope
            if (keySharedInfo2 == null || keySharedInfo2.length != 32) {
                throw new AeadException("Invalid or missing sharedInfo2 encryption key");
            }
            final SecretKey keySh2 = KEY_CONVERTOR.convertBytesToSharedSecretKey(keySharedInfo2);
            try {
                return Kmac.kmac256(keySh2, applicationSecretBytes, 32, CRYPTO4_SH2_CUSTOM_BYTES);
            } catch (Exception e) {
                throw new AeadException("KMAC calculation failed", e);
            }
        }
    }

    /**
     * Derive final Associated Data for AEAD in V4 end-to-end encryption scheme.
     * @param protocolVersion Protocol's version.
     * @param sharedInfo2 SharedInfo2, calculated by {@link #deriveSharedInfo2(EncryptorScope, String, byte[])} function.
     * @param nonce Nonce for request or response.
     * @param timestamp Timestamp for request or response.
     * @param associatedData Associated data.
     * @return Bytes representing AD parameter for V4 end-to-end encryption.
     * @throws AeadException In case that some required parameter is missing.
     */
    public static byte[] deriveAssociateDataFinal(String protocolVersion, byte[] sharedInfo2, byte[] nonce, Long timestamp, byte[] associatedData) throws AeadException {
        if (sharedInfo2 == null) {
            throw new AeadException("Missing sharedInfo2 parameter");
        }
        switch (protocolVersion) {
            case "4.0": {
                if (nonce == null) {
                    throw new AeadException("Missing nonce parameter");
                }
                if (timestamp == null) {
                    throw new AeadException("Missing timestamp parameter");
                }
                if (associatedData == null) {
                    throw new AeadException("Missing associatedData parameter");
                }
                return ByteUtils.concat(associatedData,
                        ByteUtils.concatWithSizes(
                                ByteBuffer.allocate(Long.BYTES).putLong(timestamp).array(),
                                nonce,
                                sharedInfo2));
            }
            default: {
                throw new AeadException("Invalid protocol version: " + protocolVersion);
            }
        }
    }

    /**
     * Derive final Key Context for AEAD in V4 end-to-end encryption scheme.
     * @param protocolVersion Protocol's version.
     * @param sharedInfo1 SharedInfo1 parameter.
     * @param nonce Nonce for request or response.
     * @return Bytes representing KC parameter for V4 end-to-end encryption.
     * @throws AeadException In case that some required parameter is missing.
     */
    public static byte[] deriveKeyContext(String protocolVersion, byte[] sharedInfo1, byte[] nonce) throws AeadException {
        if (sharedInfo1 == null) {
            throw new AeadException("Missing sharedInfo1 parameter");
        }
        switch (protocolVersion) {
            case "4.0": {
                if (nonce == null) {
                    throw new AeadException("Missing nonce parameter");
                }
                return ByteUtils.concat(
                        ByteUtils.encodeString(protocolVersion),
                        sharedInfo1,
                        nonce);
            }
            default: {
                throw new AeadException("Invalid protocol version: " + protocolVersion);
            }
        }
    }

}
