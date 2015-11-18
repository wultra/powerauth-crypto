package io.getlime.security.powerauth.lib.util;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Simple utility class for HMAC-SHA256 algorithm
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
public class HMACHashUtilities {
	
	/**
	 * Compute a HMAC-SHA256 of given data with provided key bytes
	 * @param data Data for the HMAC-SHA256 algorithm. 
	 * @param key Key for the HMAC-SHA256 algorithm
	 * @return HMAC-SHA256 of given data using given key.
	 */
	public byte[] hash(byte[] data, byte[] key) {
		try {
			Mac hmacSha256 = Mac.getInstance("HmacSHA256", "BC");
			SecretKey hmacKey = new SecretKeySpec(key, "HmacSHA256");
	    	hmacSha256.init(hmacKey);
	    	byte[] derivedKey = hmacSha256.doFinal(data);
	    	return derivedKey;
		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException ex) {
			Logger.getLogger(HMACHashUtilities.class.getName()).log(Level.SEVERE, null, ex);
		}
		return null;
	}

}
