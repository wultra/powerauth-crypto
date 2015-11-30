package io.getlime.security.powerauth.server.vault;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import io.getlime.security.powerauth.lib.config.PowerAuthConstants;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.lib.util.KeyConversionUtils;

public class PowerAuthServerVault {
	
	/**
	 * Return encrypted vault encryption key KEY_ENCRYPTION_VAULT using
	 * a correct KEY_ENCRYPTION_VAULT_TRANSPORT.
	 * @param serverPrivateKey Server private key KEY_SERVER_PRIVATE
	 * @param devicePublicKey Device public key KEY_DEVICE_PUBLIC
	 * @param ctr Counter CTR
	 * @return Encrypted vault encryption key. 
	 * @throws InvalidKeyException In case a provided key is incorrect.
	 */
	public byte[] encryptVaultEncryptionKey(PrivateKey serverPrivateKey, PublicKey devicePublicKey, long ctr) throws InvalidKeyException {
		try {
			KeyGenerator keyGenerator = new KeyGenerator();
			SecretKey keyMasterSecret = keyGenerator.computeSharedKey(serverPrivateKey, devicePublicKey);
			SecretKey keyMasterTransport = keyGenerator.deriveSecretKey(keyMasterSecret, PowerAuthConstants.KEY_DERIVED.TRANSPORT);
			SecretKey keyVaultEncryptionTransport = keyGenerator.deriveSecretKey(keyMasterTransport, ctr);
			SecretKey keyVaultEncryption = keyGenerator.deriveSecretKey(keyMasterSecret, PowerAuthConstants.KEY_DERIVED.ENCRYPTED_VAULT);
		
			KeyConversionUtils keyConversion = new KeyConversionUtils();
			byte[] keyVaultEncryptionBytes = keyConversion.convertSharedSecretKeyToBytes(keyVaultEncryption);
			byte[] iv = new byte[16];
			AESEncryptionUtils aes = new AESEncryptionUtils();
			return aes.encrypt(keyVaultEncryptionBytes, iv, keyVaultEncryptionTransport);
		} catch (IllegalBlockSizeException | BadPaddingException ex) {
			Logger.getLogger(PowerAuthServerVault.class.getName()).log(Level.SEVERE, null, ex);
		}
		return null;
	}

}
