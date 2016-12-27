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
package io.getlime.security.powerauth.app.cmd.util;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import org.json.simple.JSONObject;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Helper class for configuration 
 *
 * @author Petr Dvorak
 *
 */
public class ConfigurationUtils {

    private static final String expectedApplicationKey = "MTIzNDU2Nzg5MGFiY2RlZg==";
    private static final String expectedApplicationSecret = "c2VjcmV0MDAwMDAwMDAwMA==";
    private static final String expectedApplicationName = "PowerAuth 2.0 Reference Client";

    /**
     * Get application key value that is set in dictionary, or a default value.
     * @param clientConfigObject Object with configuration.
     * @return Application key.
     */
    public static String getApplicationKey(JSONObject clientConfigObject) {
        if (clientConfigObject.get("applicationId") != null) {
            return (String) clientConfigObject.get("applicationId");
        } else {
            return expectedApplicationKey;
        }
    }

    /**
     * Get application secret that is set in dictionary, or a default value.
     * @param clientConfigObject Object with configuration.
     * @return Application secret.
     */
    public static String getApplicationSecret(JSONObject clientConfigObject) {
        if (clientConfigObject.get("applicationSecret") != null) {
            return (String) clientConfigObject.get("applicationSecret");
        } else {
            return expectedApplicationSecret;
        }
    }

    /**
     * Get application name that is set in dictionary, or a default value.
     * @param clientConfigObject Object with configuration.
     * @return Application name.
     */
    public static String getApplicationName(JSONObject clientConfigObject) {
        if (clientConfigObject.get("applicationName") != null) {
            return (String) clientConfigObject.get("applicationName");
        } else {
            return expectedApplicationName;
        }
    }

    /**
     * Get master public key from the configuration object
     * @param clientConfigObject Object with configuration.
     * @return Master public key.
     */
    public static PublicKey getMasterKey(JSONObject clientConfigObject) {
        if (clientConfigObject != null && clientConfigObject.get("masterPublicKey") != null) {
            try {
                byte[] masterKeyBytes = BaseEncoding.base64().decode((String) clientConfigObject.get("masterPublicKey"));
                return PowerAuthConfiguration.INSTANCE.getKeyConvertor().convertBytesToPublicKey(masterKeyBytes);
            } catch (IllegalArgumentException e) {
                System.out.println("Master Public Key must be stored in a valid Base64 encoding");
                System.out.println();
                System.out.println("### Failed.");
                System.out.println();
                System.exit(1);
            } catch (InvalidKeySpecException e) {
                System.out.println("Master Public Key was stored in an incorrect format");
                System.out.println();
                System.out.println("### Failed.");
                System.out.println();
                System.exit(1);
            }
        } else {
            System.out.println("Master Public Key not found in the config file");
            System.out.println();
            System.out.println("### Failed.");
            System.out.println();
            System.exit(1);
        }
        return null;
    }

}
