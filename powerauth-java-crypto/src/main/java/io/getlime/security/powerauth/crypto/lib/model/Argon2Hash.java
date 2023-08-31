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
package io.getlime.security.powerauth.crypto.lib.model;

import io.getlime.security.powerauth.crypto.lib.util.SideChannelUtils;

import java.io.IOException;
import java.util.*;

/**
 * Class representing Argon2 hash in Modular Crypt Format.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class Argon2Hash {

    private String algorithm;
    private Integer version;
    private Map<String, Integer> parameters = new HashMap<>();
    private byte[] salt;
    private byte[] digest;

    /**
     * Default constructor.
     */
    private Argon2Hash() {
    }

    /**
     * Constructor with algorithm name.
     * @param algorithm Algorithm name.
     */
    public Argon2Hash(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Construct Argon2 parameters from definition in Modular Crypt Format.
     * @param input Definition in Modular Crypt Format.
     * @return Argon2 hash instance.
     * @throws IOException In case parsing of hash fails.
     */
    public static Argon2Hash parse(String input) throws IOException {
        if (input == null) {
            throw new IOException("Missing input parameter");
        }
        String[] parts = input.split("\\$");
        Argon2Hash hash = new Argon2Hash();
        if (input.matches("\\$argon2(?:i|d|id)]?\\$m=[0-9]+,t=[0-9]+,p=[0-9]+\\$[A-Za-z0-9+/]+\\$[A-Za-z0-9+/]+")) {
            // Version 16 (hex 10) of MCF syntax for Argon2
            // First part is empty, mcfRef starts with the '$' character
            hash.setAlgorithm(parts[1]);
            // Version parameter is missing in version 16, use null value
            // Parameters use syntax "m=[memoryInBytes],t=[iterations],p=[parallelism]"
            hash.setParameters(extractParameters(parts[2]));
            hash.setSalt(Base64.getDecoder().decode(parts[3]));
            hash.setDigest(Base64.getDecoder().decode(parts[4]));
            return hash;
        }
        if (input.matches("\\$argon2(?:i|d|id)?\\$v=[0-9]+\\$m=[0-9]+,t=[0-9]+,p=[0-9]+\\$[A-Za-z0-9+/]+\\$[A-Za-z0-9+/]+")) {
            // Version 19 (hex 13) of MCF syntax for Argon2
            // First part is empty, mcfRef starts with the '$' character
            hash.setAlgorithm(parts[1]);
            // Version uses syntax "v=[version]"
            Integer version = extractVersion(parts[2]);
            // Avoid reported coverity scan issue for null pointer dereference
            if (version != null) {
                hash.setVersion(version);
            }
            // Parameters use syntax "m=[memoryInBytes],t=[iterations],p=[parallelism]"
            hash.setParameters(extractParameters(parts[3]));
            hash.setSalt(Base64.getDecoder().decode(parts[4]));
            hash.setDigest(Base64.getDecoder().decode(parts[5]));
            return hash;
        }
        throw new IOException("Invalid Argon2 hash syntax");
    }

    /**
     * Get algorithm name.
     * @return Algorithm name.
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Set algorithm name.
     * @param algorithm Algorithm name.
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Get algorithm version.
     * @return Algorithm version.
     */
    public Integer getVersion() {
        return version;
    }

    /**
     * Set algorithm version.
     * @param version Algorithm version.
     */
    public void setVersion(Integer version) {
        if (version == 16) {
            // Do not set version for version 16 (hex 10)
            return;
        }
        this.version = version;
    }

    /**
     * Get algorithm parameters.
     * @return Algorithm parameters.
     */
    public Map<String, Integer> getParameters() {
        return parameters;
    }

    /**
     * Set algorithm parameters.
     * @param parameters Algorithm parameters.
     */
    public void setParameters(Map<String, Integer> parameters) {
        this.parameters = parameters;
    }

    /**
     * Get iteration count.
     * @return Iteration count.
     */
    public Integer getIterations() {
        return parameters.get("t");
    }

    /**
     * Set iteration count.
     * @param iterations Iteration count.
     */
    public void setIterations(Integer iterations) {
        parameters.put("t", iterations);
    }

    /**
     * Get memory in bytes.
     * @return Memory in bytes.
     */
    public Integer getMemory() {
        return parameters.get("m");
    }

    /**
     * Set memory in bytes.
     * @param memory Memory in bytes.
     */
    public void setMemory(Integer memory) {
        parameters.put("m", memory);
    }

    /**
     * Get parallelism parameter.
     * @return Parallelism parameter.
     */
    public Integer getParallelism() {
        return parameters.get("p");
    }

    /**
     * Set parallelism parameter.
     * @param parallelism Parallelism parameter.
     */
    public void setParallelism(Integer parallelism) {
        parameters.put("p", parallelism);
    }

    /**
     * Get salt bytes.
     * @return Salt bytes.
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * Set salt bytes.
     * @param salt Salt bytes.
     */
    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    /**
     * Get digest bytes.
     * @return Digest bytes.
     */
    public byte[] getDigest() {
        return digest;
    }

    /**
     * Set digest bytes.
     * @param digest Digest bytes.
     */
    public void setDigest(byte[] digest) {
        this.digest = digest;
    }

    /**
     * Compare Argon2 hashes.
     * @param other Other Argon2 hash.
     * @return True if hashes are identical.
     */
    public boolean hashEquals(Argon2Hash other) {
        if (digest == null || other.digest == null) {
            return false;
        }
        return SideChannelUtils.constantTimeAreEqual(digest, other.digest);
    }

    /**
     * Extract version from version definition String.
     * @param versionDef Version definition String.
     * @return Version.
     */
    private static Integer extractVersion(String versionDef) {
        if (versionDef != null && versionDef.startsWith("v=") && versionDef.length() > 2) {
            String versionStr = versionDef.substring(2);
            if (versionStr.matches("[0-9]+")) {
                return Integer.parseInt(versionStr);
            }
        }
        return null;
    }

    /**
     * Extract parameters from parameters definition String.
     * @param paramDef Parameters definition String.
     * @return Parameters.
     */
    private static Map<String, Integer> extractParameters(String paramDef) {
        Map<String, Integer> parameters = new HashMap<>();
        if (paramDef == null || !paramDef.contains(",")) {
            return parameters;
        }
        String[] parts = paramDef.split(",");
        for (String part: parts) {
            if (!part.contains("=")) {
                continue;
            }
            String[] keyValue = part.split("=");
            String key = keyValue[0];
            if (!keyValue[1].matches("[0-9]+")) {
                continue;
            }
            Integer value = Integer.parseInt(keyValue[1]);
            parameters.put(key, value);
        }
        return parameters;
    }

    /**
     * Convert version to String.
     * @return Version definition.
     */
    private String versionToString() {
        if (version == null) {
            return "";
        }
        return "v=" + version;
    }

    /**
     * Convert parameters to String.
     * @return Parameters definition.
     */
    private String parametersToString() {
        if (parameters == null || parameters.isEmpty()) {
            return "";
        }
        List<String> parts = new ArrayList<>();
        Integer memory = parameters.get("m");
        if (memory != null) {
            parts.add("m=" + memory);
        }
        Integer iterations = parameters.get("t");
        if (iterations != null) {
            parts.add("t=" + iterations);
        }
        Integer parallelism = parameters.get("p");
        if (parallelism != null) {
            parts.add("p=" + parallelism);
        }
        return String.join(",", parts);
    }

    /**
     * Convert Argon2 hash to String in Modular Crypt Format.
     * @return Argon2 hash in Modular Crypt Format
     */
    @Override
    public String toString() {
        return "$" + algorithm
                + (version != null ? "$" + versionToString() : "")
                + "$" + parametersToString()
                + "$" + Base64.getEncoder().withoutPadding().encodeToString(salt)
                + "$" + Base64.getEncoder().withoutPadding().encodeToString(digest);
    }
}
