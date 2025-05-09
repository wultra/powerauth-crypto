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
package com.wultra.security.powerauth.http;

import java.util.Map;

/**
 * Class representing the PowerAuth HTTP Authorization header "X-PowerAuth-Authorization".
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class PowerAuthAuthorizationHttpHeader extends PowerAuthHttpHeader {

    /**
     * Class with keys used in the underlying map.
     */
    public static class Key {

        /**
         * Key representing the "pa_activation_id" in the PowerAuth authorization header.
         */
        private static final String ACTIVATION_ID = "pa_activation_id";

        /**
         * Key representing the "pa_application_key" in the PowerAuth authorization header.
         */
        private static final String APPLICATION_ID = "pa_application_key";

        /**
         * Key representing the "pa_signature" in the PowerAuth authorization header.
         * <p>
         * Only applicable to protocol version 3.
         */
        private static final String SIGNATURE = "pa_signature";

        /**
         * Key representing the "pa_auth_code" in the PowerAuth authorization header.
         * <p>
         * Only applicable to protocol version 4 and newer.
         */
        private static final String AUTH_CODE = "pa_auth_code";

        /**
         * Key representing the "pa_signature_type" in the PowerAuth authorization header.
         * <p>
         * Only applicable to protocol version 3.
         */
        private static final String SIGNATURE_TYPE = "pa_signature_type";

        /**
         * Key representing the "pa_auth_code_type" in the PowerAuth authorization header.
         * <p>
         * Only applicable to protocol version 3.
         */
        private static final String AUTH_CODE_TYPE = "pa_auth_code_type";

        /**
         * Key representing the "pa_nonce" in the PowerAuth authorization header.
         */
        private static final String NONCE = "pa_nonce";

        /**
         * Key representing the "pa_version" in the PowerAuth authorization header.
         */
        private static final String VERSION = "pa_version";

    }

    /**
     * Field representing activation ID value.
     */
    private String activationId;

    /**
     * Field representing application version related key.
     */
    private String applicationKey;

    /**
     * Field representing authentication code value.
     */
    private String authCode;

    /**
     * Key representing authentication code type.
     */
    private String authCodeType;

    /**
     * Field representing nonce value.
     */
    private String nonce;

    /**
     * Field representing protocol version.
     */
    private String version;

    /**
     * Name of the PowerAuth authorization header, "X-PowerAuth-Authorization".
     */
    public static final String HEADER_NAME = "X-PowerAuth-Authorization";

    /**
     * Default constructor.
     */
    public PowerAuthAuthorizationHttpHeader() {
    }

    /**
     * Constructor with all required parameters.
     * @param activationId Activation ID.
     * @param applicationKey Application key.
     * @param authCode PowerAuth authorization code value.
     * @param authCodeType PowerAuth authorization code type.
     * @param nonce Nonce.
     * @param version Version.
     */
    public PowerAuthAuthorizationHttpHeader(String activationId, String applicationKey, String authCode, String authCodeType, String nonce, String version) {
        this.activationId = activationId;
        this.applicationKey = applicationKey;
        this.authCode = authCode;
        this.authCodeType = authCodeType;
        this.nonce = nonce;
        this.version = version;
    }

    /**
     * Create PowerAuth authorization HTTP header model object from provided string.
     * @param headerValue HTTP header with PowerAuth authorization.
     * @return PowerAuth authorization HTTP header.
     */
    @Override
    public PowerAuthAuthorizationHttpHeader fromValue(String headerValue) {
        Map<String, String> map = parseHttpHeader(headerValue);
        this.activationId         = map.get(Key.ACTIVATION_ID);
        this.applicationKey       = map.get(Key.APPLICATION_ID);
        this.nonce                = map.get(Key.NONCE);
        this.version              = map.get(Key.VERSION);
        switch (version) {
            case "3.0", "3.1", "3.2", "3.3" -> {
                this.authCode     = map.get(Key.SIGNATURE);
                this.authCodeType = map.get(Key.SIGNATURE_TYPE);
            }
            default -> {
                this.authCodeType = map.get(Key.AUTH_CODE_TYPE);
                this.authCode     = map.get(Key.AUTH_CODE);
            }
        }
        return this;
    }

    /**
     * Generate a valid PowerAuth Authorization header based on provided parameters.
     * @return Value to be used in <code>X-PowerAuth-Authorization</code> HTTP header.
     */
    public String buildHttpHeader() {
        return switch (version) {
            case "3.0", "3.1", "3.2", "3.3" -> POWERAUTH_PREFIX
                    + headerField(Key.ACTIVATION_ID, this.activationId) + ", "
                    + headerField(Key.APPLICATION_ID, this.applicationKey) + ", "
                    + headerField(Key.NONCE, this.nonce) + ", "
                    + headerField(Key.SIGNATURE_TYPE, this.authCodeType) + ", "
                    + headerField(Key.SIGNATURE, this.authCode) + ", "
                    + headerField(Key.VERSION, this.version);
            default -> POWERAUTH_PREFIX
                    + headerField(Key.ACTIVATION_ID, this.activationId) + ", "
                    + headerField(Key.APPLICATION_ID, this.applicationKey) + ", "
                    + headerField(Key.NONCE, this.nonce) + ", "
                    + headerField(Key.AUTH_CODE_TYPE, this.authCodeType) + ", "
                    + headerField(Key.AUTH_CODE, this.authCode) + ", "
                    + headerField(Key.VERSION, this.version);
        };
    }

    // Field getters

    /**
     * Get activation ID.
     * @return Activation ID.
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Get application key.
     * @return Application key.
     */
    public String getApplicationKey() {
        return applicationKey;
    }

    /**
     * Get authentication code.
     * @return Authentication code.
     */
    public String getAuthCode() {
        return authCode;
    }

    /**
     * Get authentication code type.
     * @return Authentication code type.
     */
    public String getAuthCodeType() {
        return authCodeType;
    }

    /**
     * Get nonce.
     * @return Nonce.
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * Get version.
     * @return Version.
     */
    public String getVersion() {
        return version;
    }
}
