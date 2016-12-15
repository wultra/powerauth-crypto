/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.server.signature;

import io.getlime.security.powerauth.lib.util.SignatureUtils;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
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
     * Verify a PowerAuth 2.0 signature against data using signature key list and
     * counter.
     *
     * @param data Signed data.
     * @param signature Signature for the data.
     * @param signatureKeys Keys used for signature.
     * @param ctr Counter / derived signing key index.
     * @return Returns "true" if the signature matches, "false" otherwise.
     * @throws InvalidKeyException If provided key is invalid.
     */
    public boolean verifySignatureForData(
            byte[] data,
            String signature,
            List<SecretKey> signatureKeys,
            long ctr) throws InvalidKeyException {
        return signatureUtils.validatePowerAuthSignature(data, signature, signatureKeys, ctr);
    }

}
