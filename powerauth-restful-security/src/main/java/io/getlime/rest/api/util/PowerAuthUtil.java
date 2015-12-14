package io.getlime.rest.api.util;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.springframework.security.crypto.codec.Hex;

import com.google.common.io.BaseEncoding;

public class PowerAuthUtil {

	public static String getSignatureBaseString(String httpMethod, String requestUri, String applicationSecret, String nonce, byte[] data)
			throws UnsupportedEncodingException, NoSuchAlgorithmException {

		String requestUriHash = "";
		if (requestUri != null) {
			MessageDigest shaUri = MessageDigest.getInstance("SHA-256");
			shaUri.update(requestUri.getBytes("UTF-8"));
			byte[] digest = shaUri.digest();
			requestUriHash = new String(Hex.encode(digest));
		}

		String dataBase64 = "";
		if (data != null) {
			dataBase64 = BaseEncoding.base64().encode(data);
		}

		return (httpMethod != null ? httpMethod.toUpperCase() : "GET")
				+ "&" + requestUriHash
				+ "&" + applicationSecret
				+ "&" + (nonce != null ? nonce : "")
				+ "&" + dataBase64;
	}

}
