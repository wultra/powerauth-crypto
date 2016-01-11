/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.client.app.util;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.json.simple.JSONObject;

import com.google.common.io.BaseEncoding;

import io.getlime.security.powerauth.lib.util.KeyConversionUtils;

public class ConfigurationUtils {
	
	private static final String expectedApplicationId = "a1c97807-795a-466e-87bf-230d8ac1451e";
	private static final String expectedApplicationSecret = "d358e78a-8d12-4595-bf69-6eff2c2afc04";
	private static final String expectedApplicationName = "PowerAuth 2.0 Reference Client";
	
	public static String getApplicationId(JSONObject clientConfigObject) {
		if (clientConfigObject.get("applicationId") != null) {
			return (String) clientConfigObject.get("applicationId");
		} else {
			return expectedApplicationId;
		}
	}

	public static String getApplicationSecret(JSONObject clientConfigObject) {
		if (clientConfigObject.get("applicationSecret") != null) {
			return (String) clientConfigObject.get("applicationSecret");
		} else {
			return expectedApplicationSecret;
		}
	}
	
	public static String getApplicationName(JSONObject clientConfigObject) {
		if (clientConfigObject.get("applicationName") != null) {
			return (String) clientConfigObject.get("applicationName");
		} else {
			return expectedApplicationName;
		}
	}

	public static PublicKey getMasterKey(JSONObject clientConfigObject) {
		if (clientConfigObject.get("masterPublicKey") != null) {
			try {
				byte[] masterKeyBytes = BaseEncoding.base64().decode((String) clientConfigObject.get("masterPublicKey"));
				return new KeyConversionUtils().convertBytesToPublicKey(masterKeyBytes);
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
