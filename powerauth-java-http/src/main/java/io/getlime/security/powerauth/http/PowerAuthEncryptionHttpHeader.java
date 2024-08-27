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
package io.getlime.security.powerauth.http;

import java.util.Map;

/**
 * Class representing the PowerAuth HTTP encryption header "X-PowerAuth-Encryption".
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class PowerAuthEncryptionHttpHeader extends PowerAuthHttpHeader {

    /**
     * Class with keys used in the underlying map.
     */
    public static class Key {

        /**
         * Key representing the "application_key" in the PowerAuth encryption header.
         */
        private static final String APPLICATION_KEY = "application_key";

        /**
         * Key representing the "activation_id" in the PowerAuth encryption header.
         */
        private static final String ACTIVATION_ID = "activation_id";

        /**
         * Key representing the "version" in the PowerAuth encryption header.
         */
        private static final String VERSION = "version";

    }

    /**
     * Application key.
     */
    private String applicationKey;

    /**
     * Activation ID.
     */
    private String activationId;

    /**
     * PowerAuth protocol version.
     */
    private String version;

    /**
     * Name of the PowerAuth encryption header, "X-PowerAuth-Encryption".
     */
    public static final String HEADER_NAME = "X-PowerAuth-Encryption";

    /**
     * Default constructor.
     */
    public PowerAuthEncryptionHttpHeader() {
    }

    /**
     * Constructor for application scope.
     *
     * @param applicationKey Application key.
     * @param version Version.
     */
    public PowerAuthEncryptionHttpHeader(String applicationKey, String version) {
        this.applicationKey = applicationKey;
        this.version = version;
    }

    /**
     * Constructor for activation scope.
     *
     * @param applicationKey Application key.
     * @param activationId Activation ID
     * @param version Version.
     */
    public PowerAuthEncryptionHttpHeader(String applicationKey, String activationId, String version) {
        this.applicationKey = applicationKey;
        this.activationId = activationId;
        this.version = version;
    }

    /**
     * Create PowerAuth encryption HTTP header model object from provided string.
     *
     * @param headerValue PowerAuth encryption HTTP header as String.
     * @return PowerAuth Encryption HTTP header.
     */
    @Override
    public PowerAuthEncryptionHttpHeader fromValue(String headerValue) {
        Map<String, String> map = parseHttpHeader(headerValue);
        this.applicationKey = map.get(Key.APPLICATION_KEY);
        this.activationId = map.get(Key.ACTIVATION_ID);
        this.version = map.get(Key.VERSION);
        return this;
    }

    /**
     * Generate a valid PowerAuth Encryption header based on provided parameters.
     * @return Value to be used in <code>X-PowerAuth-Encryption</code> HTTP header.
     */
    @Override
    public String buildHttpHeader() {
        return POWERAUTH_PREFIX
                + headerField(Key.APPLICATION_KEY, this.applicationKey) + ", "
                + (this.activationId == null ? "" : headerField(Key.ACTIVATION_ID, this.activationId) + ", ")
                + headerField(Key.VERSION, this.version);
    }

    /**
     * Get the application key.
     * @return Application key.
     */
    public String getApplicationKey() {
        return applicationKey;
    }

    /**
     * Get the activation ID.
     * @return Activation ID.
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Get PowerAuth protocol version.
     * @return PowerAuth protocol version.
     */
    public String getVersion() {
        return version;
    }

}
