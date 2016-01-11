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

import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.lib.util.KeyConversionUtils;

public class EncryptedStorageUtil {
	
	public static byte[] storeSignatureKnowledgeKey(char[] password, SecretKey signatureKnoweldgeSecretKey, byte[] salt, KeyGenerator keyGenerator) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		// Ask for the password and generate storage key
		SecretKey encryptionSignatureKnowledgeKey = keyGenerator.deriveSecretKeyFromPassword(new String(password), salt);

		// Encrypt the knowledge related key using the password derived key
		AESEncryptionUtils aes = new AESEncryptionUtils();
		byte[] signatureKnoweldgeSecretKeyBytes = new KeyConversionUtils().convertSharedSecretKeyToBytes(signatureKnoweldgeSecretKey);
		byte[] iv = new byte[16];
		byte[] cSignatureKnoweldgeSecretKey = aes.encrypt(signatureKnoweldgeSecretKeyBytes, iv, encryptionSignatureKnowledgeKey, "AES/CBC/NoPadding");
		return cSignatureKnoweldgeSecretKey;
	}

	public static SecretKey getSignatureKnowledgeKey(char[] password, byte[] cSignatureKnoweldgeSecretKeyBytes, byte[] salt, KeyGenerator keyGenerator) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		// Ask for the password and generate storage key
		SecretKey encryptionSignatureKnowledgeKey = keyGenerator.deriveSecretKeyFromPassword(new String(password), salt);

		// Encrypt the knowledge related key using the password derived key
		AESEncryptionUtils aes = new AESEncryptionUtils();
		byte[] iv = new byte[16];
		byte[] signatureKnoweldgeSecretKeyBytes = aes.decrypt(cSignatureKnoweldgeSecretKeyBytes, iv, encryptionSignatureKnowledgeKey, "AES/CBC/NoPadding");
		return new KeyConversionUtils().convertBytesToSharedSecretKey(signatureKnoweldgeSecretKeyBytes);
	}

}
