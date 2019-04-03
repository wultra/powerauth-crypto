/*
 * PowerAuth Crypto Library
 * Copyright 2019 Wultra s.r.o.
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

import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.model.Argon2Hash;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Utility class that provides password hashing functionality using the Argon2i algorithm.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PasswordHash {

    private static final String ALGORITHM_NAME = "argon2i";
    private static final int ALGORITHM_ID = org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_i;
    private static final int VERSION = org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_VERSION_13;
    private static final int ITERATIONS = 3;
    private static final int MEMORY_POW_2 = 15;
    private static final int PARALLELISM = 16;

    private static KeyGenerator keyGenerator = new KeyGenerator();

    /**
     * Generate hash in Argon2 Modular Crypt Format for specified password using Argon2i algorithm.
     * @param password Password bytes.
     * @return Hash String in Argon2 Modular Crypt Format.
     */
    public static String hash(byte[] password) {
        Argon2Hash argon2Hash = hash(password, null);
        return argon2Hash.toString();
    }

    /**
     * Verify password hash for specified password and password hash in Modular Crypt Format.
     * @param password Password bytes for verification.
     * @param argon2Hash Password hash in Argon2 Modular Crypt Format.
     * @return Whether password verification succeeded.
     */
    public static boolean verify(byte[] password, String argon2Hash) {
        Argon2Hash inputHash = Argon2Hash.parse(argon2Hash);
        if (inputHash == null) {
            return false;
        }
        // Verify algorithm name
        if (!ALGORITHM_NAME.equals(inputHash.getAlgorithm())) {
            return false;
        }
        // Verify algorithm version
        if (inputHash.getVersion() != VERSION) {
            return false;
        }
        // Verify iteration count
        if (inputHash.getIterations() != ITERATIONS) {
            return false;
        }
        // Extract salt from supplied hash
        byte[] salt = inputHash.getSalt();
        // Compute password digest
        Argon2Hash expectedHash = hash(password, salt);
        // Compare hash values
        return inputHash.hashEquals(expectedHash);
    }

    /**
     * Generate password hash in Argon2 Modular Crypt Format for specified password and salt using Argon2i algorithm..
     * @param password Password bytes.
     * @param salt Salt bytes, use null for random salt.
     * @return Argon2 password hash.
     */
    private static Argon2Hash hash(byte[] password, byte[] salt) {
        // In case salt is not specified, generate a random 8-byte salt
        if (salt == null) {
            salt = keyGenerator.generateRandomBytes(8);
        }

        // Set up the Argon2i algorithm
        Argon2Parameters.Builder builder = new org.bouncycastle.crypto.params.Argon2Parameters.Builder(ALGORITHM_ID)
                .withVersion(VERSION)
                .withIterations(ITERATIONS)
                .withMemoryPowOfTwo(MEMORY_POW_2)
                .withParallelism(PARALLELISM)
                .withSalt(salt);
        Argon2Parameters parameters = builder.build();

        // Generate password digest
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(parameters);
        byte[] digest = new byte[32];
        gen.generateBytes(password, digest);

        // Convert algorithm parameters and digest to Argon2 Modular Crypt Format
        Argon2Hash result = new Argon2Hash(ALGORITHM_NAME);
        result.setParameters(parameters);
        result.setDigest(digest);
        return result;
    }

}
