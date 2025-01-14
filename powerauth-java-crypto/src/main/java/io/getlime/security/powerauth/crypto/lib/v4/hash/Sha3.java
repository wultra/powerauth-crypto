package io.getlime.security.powerauth.crypto.lib.v4.hash;
/*
 * PowerAuth Crypto Library
 * Copyright 2024 Wultra s.r.o.
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
import org.bouncycastle.jcajce.provider.digest.SHA3;

/**
 * Implementation of SHA-3 algorithms (Keccak).
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class Sha3 {

    /**
     * Hash the input data using SHA3-256.
     *
     * @param originalBytes Input bytes.
     * @return Hashed bytes.
     */
    public static byte[] hash256(byte[] originalBytes) {
        return digest256(originalBytes);
    }

    /**
     * Hash the input data using SHA3-384.
     *
     * @param originalBytes Input bytes.
     * @return Hashed bytes.
     */
    public static byte[] hash384(byte[] originalBytes) {
        return digest384(originalBytes);
    }

    private static byte[] digest256(byte[] originalBytes) {
        final SHA3.DigestSHA3 sha3_256 = new SHA3.Digest256();
        return sha3_256.digest(originalBytes);
    }

    private static byte[] digest384(byte[] originalBytes) {
        final SHA3.DigestSHA3 sha3_384 = new SHA3.Digest384();
        return sha3_384.digest(originalBytes);
    }

}