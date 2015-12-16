package io.getlime.security.powerauth.lib.util.http;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PowerAuthHttpHeader {
	
	public static final String ACTIVATION_ID = "pa_activation_id";
	public static final String APPLICATION_ID = "pa_application_id";
	public static final String SIGNATURE = "pa_signature";
	public static final String SIGNATURE_TYPE = "pa_signature_type";
	public static final String NONCE = "pa_nonce";
	public static final String VERSION = "pa_version";
	
	private static final String POWERAUTH_PREFIX = "PowerAuth ";

	public static Map<String, String> parsePowerAuthSignatureHTTPHeader(String xPowerAuthSignatureHeader) {
		xPowerAuthSignatureHeader = xPowerAuthSignatureHeader.trim();
		if (!xPowerAuthSignatureHeader.startsWith(POWERAUTH_PREFIX)) {
			return null;
		}
		xPowerAuthSignatureHeader = xPowerAuthSignatureHeader.substring(POWERAUTH_PREFIX.length());
		
		// Parse the key / value pairs
		Map<String, String> result = new HashMap<>();
		Pattern p = Pattern.compile("(\\w+)=\"*((?<=\")[^\"]+(?=\")|([^\\s]+)),*\"*");
		Matcher m = p.matcher(xPowerAuthSignatureHeader);
		while(m.find()){
		    result.put(m.group(1), m.group(2));
		}

		return result;
	}
	
	private static String headerField(String key, String value) {
		return " " + key + "=\"" + value + "\"";
	}
	
	public static String getPowerAuthSignatureHTTPHeader(String activationId, String applicationId, String nonce, String signatureType, String signature, String version) {
		String result = POWERAUTH_PREFIX
				+ headerField(ACTIVATION_ID, activationId) + ", "
				+ headerField(APPLICATION_ID, applicationId) + ", "
				+ headerField(NONCE, nonce) + ", "
				+ headerField(SIGNATURE_TYPE, signatureType) + ", "
				+ headerField(SIGNATURE, signature) + ", "
				+ headerField(VERSION, version);
		return result;
	}

}
