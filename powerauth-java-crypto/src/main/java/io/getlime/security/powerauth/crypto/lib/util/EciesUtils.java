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
package io.getlime.security.powerauth.crypto.lib.util;

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.exception.EciesException;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * A utility class for handling ECIES data.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public final class EciesUtils {

    /**
     * Private constructor.
     */
    private EciesUtils() {
    }

    /**
     * Generate MAC data for ECIES request or response MAC validation.
     *
     * @param sharedInfo2 Parameter sharedInfo2 for ECIES.
     * @param encryptedData Encrypted data
     * @return Resolved MAC data.
     */
    public static byte[] generateMacData(final byte[] sharedInfo2, final byte[] encryptedData) {
        return ByteUtils.concat(encryptedData, sharedInfo2);
    }

    /**
     * Generate timestamp for ECIES request/response.
     *
     * @return Timestamp bytes to use for ECIES encryption.
     */
    public static long generateTimestamp() {
        // Protocol V3.2+
        return System.currentTimeMillis();
    }

    /**
     * Derive associated data for ECIES.
     * @param scope Encryptor's scope.
     * @param protocolVersion Protocol version.
     * @param applicationKey Application key.
     * @param activationId Activation ID.
     * @param temporaryKeyId Temporary key ID.
     * @return Derived associated data.
     * @throws EciesException In case that activation ID is required but is missing.
     */
    public static byte[] deriveAssociatedData(EncryptorScope scope, String protocolVersion, String applicationKey, String activationId, String temporaryKeyId) throws EciesException {
        if (protocolVersion == null) {
            throw new EciesException("Protocol version is missing");
        }
        switch (protocolVersion) {
            case "3.2": {
                if (applicationKey == null) {
                    throw new EciesException("Application key is missing");
                }
                if (scope == EncryptorScope.ACTIVATION_SCOPE) {
                    if (activationId == null) {
                        throw new EciesException("Activation ID is missing in ACTIVATION_SCOPE");
                    }
                    return ByteUtils.concatStrings(protocolVersion, applicationKey, activationId);
                } else {
                    return ByteUtils.concatStrings(protocolVersion, applicationKey);
                }
            }
            case "3.3": {
                if (applicationKey == null) {
                    throw new EciesException("Application key is missing");
                }
                if (temporaryKeyId == null) {
                    throw new EciesException("Missing temporary key identifier");
                }
                if (scope == EncryptorScope.ACTIVATION_SCOPE) {
                    if (activationId == null) {
                        throw new EciesException("Activation ID is missing in ACTIVATION_SCOPE");
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
     * Derive base for SharedInfo2 calculation for ECIES encryption scheme.
     * @param scope Scope of the encryptor.
     * @param applicationSecret Application's secret.
     * @param transportKey Transport key, required when scope is {@link EncryptorScope#ACTIVATION_SCOPE}.
     * @return Bytes representing SharedInfo2 base.
     * @throws EciesException In case of some required parameter is missing or if underlying cryptographic primitive fail.
     */
    public static byte[] deriveSharedInfo2Base(EncryptorScope scope, String applicationSecret, byte[] transportKey) throws EciesException {
        if (applicationSecret == null) {
            throw new EciesException("Missing applicationSecret parameter");
        }
        final byte[] applicationSecretBytes = applicationSecret.getBytes(StandardCharsets.UTF_8);
        if (scope == EncryptorScope.APPLICATION_SCOPE) {
            // Application scope
            return Hash.sha256(applicationSecretBytes);
        } else {
            // Activation scope
            if (transportKey == null || transportKey.length != 16) {
                throw new EciesException("Invalid or missing transportKey");
            }
            try {
                return new HMACHashUtilities().hash(transportKey, applicationSecretBytes);
            } catch (Exception e) {
                throw new EciesException("HMAC calculation failed", e);
            }
        }
    }

    /**
     * Derive final SharedInfo2 constant for ECIES encryption scheme.
     * @param protocolVersion Protocol's version.
     * @param sharedInfo2Base SharedInfo2 base, calculated by {@link #deriveSharedInfo2Base(EncryptorScope, String, byte[])} function.
     * @param ephemeralPublicKey Ephemeral public key. Value is null for response encryption / decryption.
     * @param nonce Nonce for request or response.
     * @param timestamp Timestamp for request or response.
     * @param associatedData Associated data.
     * @return Bytes representing SharedInfo2 parameter for ECIES encryption.
     * @throws EciesException In case that some required parameter is missing.
     */
    public static byte[] deriveSharedInfo2(String protocolVersion, byte[] sharedInfo2Base, byte[] ephemeralPublicKey, byte[] nonce, Long timestamp, byte[] associatedData) throws EciesException {
        if (sharedInfo2Base == null) {
            throw new EciesException("Missing sharedInfo2Base parameter");
        }
        switch (protocolVersion) {
            case "3.3", "3.2": {
                if (nonce == null) {
                    throw new EciesException("Missing nonce parameter");
                }
                if (timestamp == null) {
                    throw new EciesException("Missing timestamp parameter");
                }
                if (associatedData == null) {
                    throw new EciesException("Missing associatedData parameter");
                }
                return ByteUtils.concatWithSizes(
                        sharedInfo2Base,
                        nonce,
                        ByteBuffer.allocate(Long.BYTES).putLong(timestamp).array(),
                        ephemeralPublicKey,
                        associatedData);
            }
            default: {
                return sharedInfo2Base;
            }
        }
    }

}
