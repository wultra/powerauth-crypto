package io.getlime.security.client.app.util;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.json.simple.JSONObject;

import com.google.common.io.BaseEncoding;

import io.getlime.security.powerauth.lib.util.KeyConversionUtils;

public class ConfigurationUtils {
	
	private static final String expectedApplicationId = "a1c97807-795a-466e-87bf-230d8ac1451e";
	private static final String expectedApplicationSecret = "d358e78a-8d12-4595-bf69-6eff2c2afc04";
	
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
