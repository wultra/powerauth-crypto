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
package io.getlime.security.powerauth.crypto.lib.generator;

import com.google.common.io.BaseEncoding;

import java.security.SecureRandom;
import java.util.UUID;

/**
 * Generator of identifiers used in Poweruth protocol.
 *
 * @author Petr Dvorak
 *
 */
public class IdentifierGenerator {

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generate a new random activation ID - a UUID level 4 instance.
     *
     * @return New pseudo-random activation ID.
     */
    public String generateActivationId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generate a new short activation ID. The format of short activation ID is
     * "ABCDE-FGHIJ" - two components, each of them 5 random characters from
     * Base32 encoding, separated by "-" character.
     *
     * @return A new short activation ID.
     */
    public String generateActivationIdShort() {
        return generateBase32Token(5, secureRandom)
                + "-"
                + generateBase32Token(5, secureRandom);
    }

    /**
     * Generate a new activation OTP. The format of activation OTP is
     * "ABCDE-FGHIJ" - two components, each of them 5 random characters from
     * Base32 encoding, separated by "-" character.
     *
     * @return A new activation OTP.
     */
    public String generateActivationOTP() {
        return generateBase32Token(5, secureRandom)
                + "-"
                + generateBase32Token(5, secureRandom);
    }

    /**
     * Generate a new string with characters from Base32 encoding, with given
     * length. Because the routines calling this method may call it more than
     * once, an instance of SecureRandom is passed as one of the parameters.
     *
     * @param length Length of the resulting random string.
     * @param random An instance of SecureRandom.
     * @return New string with Base32 characters of a given length.
     */
    private String generateBase32Token(int length, SecureRandom random) {
        byte[] randomBytes = new byte[length];
        random.nextBytes(randomBytes);
        return BaseEncoding.base32().omitPadding().encode(randomBytes).substring(0, length);
    }

}
