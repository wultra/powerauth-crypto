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
package io.getlime.security.powerauth.crypto.lib.util;

import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * Class that is used for computing EC public key fingerprint. Goal of the public key fingerprint is to
 * enable user to visually check that the public key was successfully exchanged between client and server.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class ECPublicKeyFingerprint {

    public static String compute(ECPublicKey publicKey) throws NoSuchAlgorithmException {
        byte[] devicePublicKeyBytes = publicKey.getW().getAffineX().toByteArray();
        if (devicePublicKeyBytes[0] == 0x00) {
            devicePublicKeyBytes = Arrays.copyOfRange(devicePublicKeyBytes, 1, 33);
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(devicePublicKeyBytes);
        if (hash.length < 4) { // assert
            throw new IndexOutOfBoundsException();
        }
        int index = hash.length - 4;
        int number = (ByteBuffer.wrap(hash).getInt(index) & 0x7FFFFFFF) % (int) (Math.pow(10, PowerAuthConfiguration.FINGERPRINT_LENGTH));
        return String.format("%0" + PowerAuthConfiguration.SIGNATURE_LENGTH + "d", number);
    }
}
