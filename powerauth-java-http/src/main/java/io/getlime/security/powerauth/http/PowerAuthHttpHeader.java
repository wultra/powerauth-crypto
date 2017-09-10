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
package io.getlime.security.powerauth.http;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helper class simplifying working with PowerAuth HTTP Authorization header "X-PowerAuth-Authorization".
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthHttpHeader {

    /**
     * Class with keys used in the underlying map.
     */
    public class Key {

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
         */
        private static final String SIGNATURE = "pa_signature";

        /**
         * Key representing the "pa_signature_type" in the PowerAuth authorization header.
         */
        private static final String SIGNATURE_TYPE = "pa_signature_type";

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
     * Field representing signature value.
     */
    private String signature;

    /**
     * Key representing signature type.
     */
    private String signatureType;

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

    private static final String POWERAUTH_PREFIX = "PowerAuth ";

    /**
     * Parse the PowerAuth authorization header and return map with values.
     * @param xPowerAuthSignatureHeader HTTP header with PowerAuth authorization.
     * @return Map with parsed header values.
     */
    public static Map<String, String> parsePowerAuthSignatureHTTPHeader(String xPowerAuthSignatureHeader) {
        if (xPowerAuthSignatureHeader == null) {
            return new HashMap<>(); // invalid map with empty values works better than null here
        }
        xPowerAuthSignatureHeader = xPowerAuthSignatureHeader.trim();
        if (!xPowerAuthSignatureHeader.startsWith(POWERAUTH_PREFIX)) {
            return new HashMap<>(); // invalid map with empty values works better than null here
        }
        xPowerAuthSignatureHeader = xPowerAuthSignatureHeader.substring(POWERAUTH_PREFIX.length()).trim();

        // Parse the key / value pairs
        Map<String, String> result = new HashMap<>();
        Pattern p = Pattern.compile("(\\w+)=\"*((?<=\")[^\"]+(?=\")|([^\\s]+)),*\"*");
        Matcher m = p.matcher(xPowerAuthSignatureHeader);
        while (m.find()) {
            result.put(m.group(1), m.group(2));
        }

        return result;
    }

    public static PowerAuthHttpHeader fromValue(String headerValue) {
        Map<String, String> map = parsePowerAuthSignatureHTTPHeader(headerValue);
        PowerAuthHttpHeader header  = new PowerAuthHttpHeader();
        header.activationId         = map.get(Key.ACTIVATION_ID);
        header.applicationKey       = map.get(Key.APPLICATION_ID);
        header.nonce                = map.get(Key.NONCE);
        header.signatureType        = map.get(Key.SIGNATURE_TYPE);
        header.signature            = map.get(Key.SIGNATURE);
        header.version              = map.get(Key.VERSION);
        return header;
    }

    private static String headerField(String key, String value) {
        return key + "=\"" + value + "\"";
    }

    /**
     * Generate a valid PowerAuth Authorization header based on provided parameters.
     * @param activationId An ID of an activation.
     * @param applicationId An ID of an application.
     * @param nonce Random nonce.
     * @param signatureType Signature type.
     * @param signature Signature.
     * @param version PowerAuth protocol version.
     * @return Value to be used in <code>X-PowerAuth-Authorization</code> HTTP header.
     */
    public static String getPowerAuthSignatureHTTPHeader(String activationId, String applicationId, String nonce, String signatureType, String signature, String version) {
        String result = POWERAUTH_PREFIX
                + headerField(Key.ACTIVATION_ID, activationId) + ", "
                + headerField(Key.APPLICATION_ID, applicationId) + ", "
                + headerField(Key.NONCE, nonce) + ", "
                + headerField(Key.SIGNATURE_TYPE, signatureType) + ", "
                + headerField(Key.SIGNATURE, signature) + ", "
                + headerField(Key.VERSION, version);
        return result;
    }

    // Field getters

    public String getActivationId() {
        return activationId;
    }

    public String getApplicationKey() {
        return applicationKey;
    }

    public String getSignature() {
        return signature;
    }

    public String getSignatureType() {
        return signatureType;
    }

    public String getNonce() {
        return nonce;
    }

    public String getVersion() {
        return version;
    }
}
