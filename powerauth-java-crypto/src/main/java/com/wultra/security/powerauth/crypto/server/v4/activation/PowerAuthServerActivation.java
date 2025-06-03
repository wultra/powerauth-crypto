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
package com.wultra.security.powerauth.crypto.server.v4.activation;

import com.wultra.security.powerauth.crypto.lib.enums.EcCurve;
import com.wultra.security.powerauth.crypto.lib.enums.ProtocolVersion;
import com.wultra.security.powerauth.crypto.lib.generator.KeyGenerator;
import com.wultra.security.powerauth.crypto.lib.model.ActivationStatusBlobInfo;
import com.wultra.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import com.wultra.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import com.wultra.security.powerauth.crypto.lib.util.*;
import com.wultra.security.powerauth.crypto.lib.v4.PqcDsa;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.CustomString;
import com.wultra.security.powerauth.crypto.lib.v4.kdf.Kmac;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Class implementing cryptography used on a server side in order to assure
 * PowerAuth Server activation related processes (V4).
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthServerActivation {

    private static final KeyGenerator KEY_GENERATOR = new KeyGenerator();
    private static final SignatureUtils SIGNATURE_UTILS = new SignatureUtils();
    private static final PqcDsa PQC_DSA = new PqcDsa();

    /**
     * Custom bytes for MAC for counter data.
     */
    private static final byte[] KMAC_STATUS_CUSTOM_BYTES = CustomString.PA4MAC_STATUS.value().getBytes(StandardCharsets.UTF_8);

    /**
     * Generate a server related activation EC key pair.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @return A new server key pair.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public KeyPair generateEcServerKeyPair() throws CryptoProviderException {
        return KEY_GENERATOR.generateKeyPair(EcCurve.P384);
    }

    /**
     * Generate a server related activation PQC key pair.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @return A new server key pair.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public KeyPair generatePqcServerKeyPair() throws CryptoProviderException {
        return PQC_DSA.generateKeyPair();
    }

    /**
     * Generate signature for the activation code.
     * <p>
     * Signature is then computed using the master private key.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param activationCode Short activation ID.
     * @param masterPrivateKey Master Private Key.
     * @return Signature of activation data using Master Private Key.
     * @throws InvalidKeyException In case Master Private Key is invalid.
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] generateActivationSignature(String activationCode,
                                              PrivateKey masterPrivateKey) throws InvalidKeyException, GenericCryptoException, CryptoProviderException {
        byte[] bytes = activationCode.getBytes(StandardCharsets.UTF_8);
        return SIGNATURE_UTILS.computeECDSASignature(EcCurve.P384, bytes, masterPrivateKey);
    }

    /**
     * Generate activations status blob for different protocol versions.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param statusBlobInfo Activation status blog information.
     * @param protocolVersion Protocol version.
     * @return Status blob byte array.
     * @throws GenericCryptoException In case encryption fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public byte[] generateStatusBlob(ActivationStatusBlobInfo statusBlobInfo, ProtocolVersion protocolVersion) throws GenericCryptoException, CryptoProviderException {
        final byte[] ctrDataHash;
        final byte ctrByte;
        final byte ctrLookAhead;
        final int magicValue;
        final byte[] statusFlagsAndReserved;
        final int blobLength;
        if (protocolVersion.getMajorVersion() != 4) {
            throw new GenericCryptoException("Unsupported protocol version: " + protocolVersion);
        }
        if (statusBlobInfo.getCtrDataHash() == null) {
            throw new GenericCryptoException("Missing ctrDataHash in statusBlobInfo object");
        }
        magicValue = ActivationStatusBlobInfo.ACTIVATION_STATUS_MAGIC_VALUE_V4;
        // Status flags 1 byte + reserved 5 bytes
        statusFlagsAndReserved = ByteBuffer.allocate(5)
                .put(statusBlobInfo.getStatusFlags())
                .put(KEY_GENERATOR.generateRandomBytes(4))
                .array();
        ctrDataHash = statusBlobInfo.getCtrDataHash();
        ctrByte = statusBlobInfo.getCtrByte();
        ctrLookAhead = statusBlobInfo.getCtrLookAhead();
        blobLength = 48;
        return ByteBuffer.allocate(blobLength)
                .putInt(magicValue)                          // 4 bytes
                .put(statusBlobInfo.getActivationStatus())   // 1 byte
                .put(statusBlobInfo.getCurrentVersion())     // 1 byte
                .put(statusBlobInfo.getUpgradeVersion())     // 1 byte
                .put(statusFlagsAndReserved)                 // 5 bytes
                .put(ctrByte)                                // 1 byte
                .put(statusBlobInfo.getFailedAttempts())     // 1 byte
                .put(statusBlobInfo.getMaxFailedAttempts())  // 1 byte
                .put(ctrLookAhead)                           // 1 byte
                .put(ctrDataHash)                            // 16 bytes
                .array();
    }

    /**
     * Calculate MAC for activation status.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param statusData Activation status data.
     * @param keyCtrStatusMac Key for calculating MAC for activation data.
     * @param protocolVersion Protocol version.
     * @return Activation status MAC.
     * @throws GenericCryptoException In case of a cryptography error.
     */
    public byte[] calculateStatusMac(byte[] statusData, SecretKey keyCtrStatusMac, ProtocolVersion protocolVersion) throws GenericCryptoException {
        if (protocolVersion.getMajorVersion() != 4) {
            throw new GenericCryptoException("Unsupported protocol version: " + protocolVersion);
        }
        return Kmac.kmac256(keyCtrStatusMac, statusData, KMAC_STATUS_CUSTOM_BYTES);
    }

    /**
     * Compute a fingerprint for the version 4 activation for algorithm EC_P384. The fingerprint can be used for visual validation of exchanged device public key.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param devicePublicKey Device public key.
     * @param serverPublicKey Server public key.
     * @param activationId Activation ID.
     * @return Fingerprint of the public key.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws GenericCryptoException In case fingerprint could not be calculated.
     */
    public String computeActivationEcFingerprint(PublicKey devicePublicKey, PublicKey serverPublicKey, String activationId) throws GenericCryptoException, CryptoProviderException {
        // TODO - support for crypto4
        return "";
    }

    /**
     * Compute a fingerprint for the version 4 activation for algorithm EC_P384_ML_L3. The fingerprint can be used for visual validation of exchanged device public key.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param ecDevicePublicKey EC device public key.
     * @param pqcDevicePublicKey PQC device public key.
     * @param ecServerPublicKey EC server public key.
     * @param pqcServerPublicKey PQC server public key.
     * @param activationId Activation ID.
     * @return Fingerprint of the public keys.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws GenericCryptoException In case fingerprint could not be calculated.
     */
    public String computeActivationHybridFingerprint(PublicKey ecDevicePublicKey, PublicKey pqcDevicePublicKey, PublicKey ecServerPublicKey, PublicKey pqcServerPublicKey, String activationId) throws GenericCryptoException, CryptoProviderException {
        // TODO - support for crypto4
        return "";
    }

    /**
     * Calculate hash from value representing the hash based counter. HMAC-SHA256 is currently used as a hashing
     * function.
     *
     * <p><b>PowerAuth protocol versions:</b>
     * <ul>
     *     <li>4.0</li>
     * </ul>
     *
     * @param ctrData Hash-based counter.
     * @param keyCtrDataMac Key for calculating the counter data hash.
     * @param protocolVersion Protocol version.
     * @return Hash calculated from provided hash-based counter.
     * @throws GenericCryptoException In case that key derivation fails or you provided invalid ctrData.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     * @throws InvalidKeyException In case that transport key is not valid.
     */
    public byte[] calculateHashFromHashBasedCounter(byte[] ctrData, SecretKey keyCtrDataMac, ProtocolVersion protocolVersion)
            throws CryptoProviderException, InvalidKeyException, GenericCryptoException {
        if (protocolVersion.getMajorVersion() != 4) {
            throw new GenericCryptoException("Unsupported protocol version: " + protocolVersion);
        }
        return new HashBasedCounterUtils().calculateHashFromHashBasedCounter(ctrData, keyCtrDataMac, protocolVersion);
    }

}
