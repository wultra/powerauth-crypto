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
 * Class representing the PowerAuth HTTP Token header "X-PowerAuth-Token".
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class PowerAuthTokenHttpHeader extends PowerAuthHttpHeader {

    /**
     * Class with keys used in the underlying map.
     */
    public static class Key {

        /**
         * Key representing the "token_id" in the PowerAuth token header.
         */
        private static final String TOKEN_ID = "token_id";

        /**
         * Key representing the "token_digest" in the PowerAuth token header.
         */
        private static final String TOKEN_DIGEST = "token_digest";

        /**
         * Key representing the "token_nonce" in the PowerAuth token header.
         */
        private static final String NONCE = "nonce";

        /**
         * Key representing the "timestamp" in the PowerAuth token header.
         */
        private static final String TIMESTAMP = "timestamp";

        /**
         * Key representing the "version" in the PowerAuth token header.
         */
        private static final String VERSION = "version";

    }

    /**
     * Token ID used for token lookup.
     */
    private String tokenId;

    /**
     * Token digest representing the computed credentials.
     */
    private String tokenDigest;

    /**
     * Random nonce.
     */
    private String nonce;

    /**
     * Timestamp when the token was generated.
     */
    private String timestamp;

    /**
     * Token version.
     */
    private String version;

    /**
     * Name of the PowerAuth token header, "X-PowerAuth-Token".
     */
    public static final String HEADER_NAME = "X-PowerAuth-Token";

    /**
     * Default constructor.
     */
    public PowerAuthTokenHttpHeader() {
    }

    /**
     * Constructor with all required class attributes.
     * @param tokenId Token ID.
     * @param tokenDigest Token digest.
     * @param nonce Nonce.
     * @param timestamp Timestamp.
     * @param version Version.
     */
    public PowerAuthTokenHttpHeader(String tokenId, String tokenDigest, String nonce, String timestamp, String version) {
        this.tokenId = tokenId;
        this.tokenDigest = tokenDigest;
        this.nonce = nonce;
        this.timestamp = timestamp;
        this.version = version;
    }

    /**
     * Create PowerAuth token HTTP header model object from provided string.
     * @param headerValue HTTP header with PowerAuth token.
     * @return PowerAuth token HTTP header.
     */
    @Override
    public PowerAuthTokenHttpHeader fromValue(String headerValue) {
        Map<String, String> map = parseHttpHeader(headerValue);
        this.tokenId          = map.get(Key.TOKEN_ID);
        this.tokenDigest      = map.get(Key.TOKEN_DIGEST);
        this.nonce            = map.get(Key.NONCE);
        this.timestamp        = map.get(Key.TIMESTAMP);
        this.version          = map.get(Key.VERSION);
        return this;
    }

    @Override
    public String buildHttpHeader() {
        return POWERAUTH_PREFIX
                + headerField(Key.TOKEN_ID, this.tokenId) + ", "
                + headerField(Key.TOKEN_DIGEST, this.tokenDigest) + ", "
                + headerField(Key.NONCE, this.nonce) + ", "
                + headerField(Key.TIMESTAMP, this.timestamp) + ", "
                + headerField(Key.VERSION, this.version);
    }

    // Field getters

    /**
     * Get token identifier.
     * @return Token identifier.
     */
    public String getTokenId() {
        return tokenId;
    }

    /**
     * Get token digest.
     * @return Token digest.
     */
    public String getTokenDigest() {
        return tokenDigest;
    }

    /**
     * Get nonce.
     * @return Nonce.
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * Get timestamp.
     * @return Timestamp.
     */
    public String getTimestamp() {
        return timestamp;
    }

    /**
     * Get version.
     * @return Version.
     */
    public String getVersion() {
        return version;
    }
}
