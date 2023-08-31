/*
 * PowerAuth Crypto Library
 * Copyright 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.crypto.server.signature;

import io.getlime.security.powerauth.crypto.lib.config.SignatureConfiguration;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.crypto.lib.util.SignatureUtils;

import javax.crypto.SecretKey;
import java.util.List;

/**
 * Class implementing processes PowerAuth Server uses to compute and validate
 * signatures. 
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthServerSignature {

    private final SignatureUtils signatureUtils = new SignatureUtils();

    /**
     * Verify a PowerAuth signature against data using signature key list and
     * counter.
     *
     * @param data Signed data.
     * @param signature Signature for the data.
     * @param signatureKeys Keys used for signature.
     * @param ctrData Hash based counter / derived signing key index.
     * @param signatureConfiguration Format and parameters of signature to verify.
     * @return Returns "true" if the signature matches, "false" otherwise.
     * @throws GenericCryptoException In case signature computation fails.
     * @throws CryptoProviderException In case cryptography provider is incorrectly initialized.
     */
    public boolean verifySignatureForData(byte[] data, String signature, List<SecretKey> signatureKeys, byte[] ctrData, SignatureConfiguration signatureConfiguration) throws GenericCryptoException, CryptoProviderException {
        return signatureUtils.validatePowerAuthSignature(data, signature, signatureKeys, ctrData, signatureConfiguration);
    }

}
