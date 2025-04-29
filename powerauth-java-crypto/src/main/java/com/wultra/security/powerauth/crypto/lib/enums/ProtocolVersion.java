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

package com.wultra.security.powerauth.crypto.lib.enums;

import lombok.Getter;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Enumeration of supported protocol versions.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Getter
public enum ProtocolVersion {

    /**
     * Protocol version 3.0
     */
    V30("3.0"),
    /**
     * Protocol version 3.1
     */
    V31("3.1"),
    /**
     * Protocol version 3.2
     */
    V32("3.2"),
    /**
     * Protocol version 3.3
     */
    V33("3.3"),
    /**
     * Protocol version 4.0
     */
    V40("4.0");

    private final String version;

    /**
     * Protocol version constructor.
     * @param version Version.
     */
    ProtocolVersion(String version) {
        this.version = version;
    }

    /**
     * Return the list of supported protocol versions.
     * @return Set of supported protocol versions.
     */
    public static Set<String> supportedVersions() {
        return Arrays.stream(values()).map(value -> value.version).collect(Collectors.toSet());
    }

    /**
     * Return the major version.
     * @return Integer value of the major version.
     */
    public int getMajorVersion() {
        return Integer.parseInt(version.split("\\.")[0]);
    }

    /**
     * Get protocol version from String value.
     * @param value String protocol version value.
     * @return Protocol version.
     */
    public static ProtocolVersion fromValue(String value) {
        return Arrays.stream(ProtocolVersion.values())
                .filter(version -> version.getVersion().equals(value))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Unsupported protocol version: " + value));
    }
}
