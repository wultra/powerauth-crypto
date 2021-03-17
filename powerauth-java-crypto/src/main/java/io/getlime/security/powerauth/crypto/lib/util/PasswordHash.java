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
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Utility class that provides password hashing functionality using the Argon2 algorithm.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PasswordHash {

    // Default Argon2 password hashing algorithm configuration
    private static final int ALGORITHM_ID = Argon2Parameters.ARGON2_i;
    private static final int VERSION = Argon2Parameters.ARGON2_VERSION_13;
    private static final int ITERATIONS = 3;
    private static final int MEMORY_POW_2 = 15;
    private static final int PARALLELISM = 16;
    private static final int SALT_SIZE = 16;

    // Conversion of algorithm ID to algorithm name for Argon2
    private static final Map<Integer, String> ALGORITHM_NAME_MAP = new LinkedHashMap<>();
    static {
        ALGORITHM_NAME_MAP.put(Argon2Parameters.ARGON2_i, "argon2i");
        ALGORITHM_NAME_MAP.put(Argon2Parameters.ARGON2_d, "argon2d");
        ALGORITHM_NAME_MAP.put(Argon2Parameters.ARGON2_id, "argon2id");
    }

    private static final KeyGenerator keyGenerator = new KeyGenerator();

    /**
     * Generate hash in Argon2 Modular Crypt Format for specified password using Argon2i algorithm.
     * @param password Password bytes.
     * @return Hash String in Argon2 Modular Crypt Format.
     * @throws CryptoProviderException In case key cryptography provider is incorrectly initialized.
     */
    public static String hash(byte[] password) throws CryptoProviderException {
        // Generate random salt
        byte[] salt = keyGenerator.generateRandomBytes(SALT_SIZE);
        // Set up the Argon2i algorithm with default parameters
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(ALGORITHM_ID)
                .withVersion(VERSION)
                .withIterations(ITERATIONS)
                .withMemoryPowOfTwo(MEMORY_POW_2)
                .withParallelism(PARALLELISM)
                .withSalt(salt);
        Argon2Parameters parameters = builder.build();
        Argon2Hash argon2Hash = hash(password, parameters);
        return argon2Hash.toString();
    }

    /**
     * Verify password hash for specified password and password hash in Modular Crypt Format.
     * @param password Password bytes for verification.
     * @param argon2Hash Password hash in Argon2 Modular Crypt Format.
     * @return Whether password verification succeeded.
     * @throws IOException In case parsing of hash fails.
     */
    public static boolean verify(byte[] password, String argon2Hash) throws IOException {
        Argon2Hash input = Argon2Hash.parse(argon2Hash);
        // Convert algorithm name to algorithm ID
        int algorithmId = Argon2Parameters.ARGON2_i;
        for (Map.Entry<Integer, String> entry: ALGORITHM_NAME_MAP.entrySet()) {
            if (entry.getValue().equals(input.getAlgorithm())) {
                algorithmId = entry.getKey();
                break;
            }
        }
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(algorithmId)
                .withVersion(input.getVersion())
                .withIterations(input.getIterations())
                .withMemoryAsKB(input.getMemory())
                .withParallelism(input.getParallelism())
                .withSalt(input.getSalt());
        Argon2Parameters parameters = builder.build();
        // Compute password hash using provided parameters
        Argon2Hash expectedHash = hash(password, parameters);
        // Compare hash values
        return input.hashEquals(expectedHash);
    }

    /**
     * Generate password hash in Argon2 Modular Crypt Format for specified password and salt using Argon2i algorithm..
     * @param password Password bytes.
     * @param parameters Argon2 parameters.
     * @return Argon2 password hash.
     */
    private static Argon2Hash hash(byte[] password, Argon2Parameters parameters) {
        // Generate password digest
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(parameters);
        byte[] digest = new byte[32];
        gen.generateBytes(password, digest);

        // Convert algorithm parameters and digest to Argon2 Modular Crypt Format
        String algorithmName = ALGORITHM_NAME_MAP.get(parameters.getType());
        Argon2Hash result = new Argon2Hash(algorithmName);
        result.setVersion(parameters.getVersion());
        result.setIterations(parameters.getIterations());
        result.setParallelism(parameters.getLanes());
        result.setMemory(parameters.getMemory());
        result.setSalt(parameters.getSalt());
        result.setDigest(digest);
        return result;
    }

}
