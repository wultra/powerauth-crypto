package io.getlime.security.powerauth.client.vault;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import io.getlime.security.powerauth.lib.config.PowerAuthConstants;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.util.AESEncryptionUtils;
import io.getlime.security.powerauth.lib.util.KeyConversionUtils;

public class PowerAuthClientVault {
	
	/**
	 * Derive a vault encryption key KEY_ENCRYPTION_VAULT used for storing
	 * records in secure vault.
	 * @param keyMasterSecret Master secret key KEY_MASTER_SECRET.
	 * @return A new derived transport key.
	 */
	public SecretKey deriveVaultEncryptionKey(SecretKey keyMasterSecret) {
		KeyGenerator keyGen = new KeyGenerator();
		return keyGen.deriveSecretKey(keyMasterSecret, PowerAuthConstants.KEY_DERIVED.ENCRYPTED_VAULT);
	}
	
	/**
	 * Decrypts the vault encryption key KEY_ENCRYPTION_VAULT using a transport key
	 * KEY_ENCRYPTION_VAULT_TRANSPORT.
	 * @param cVaultEncryptionKey Encrypted vault encryption key KEY_ENCRYPTION_VAULT.
	 * @param vaultEncryptionTransportKey Key used for decrypting vault encryption key.
	 * @return Original KEY_ENCRYPTION_VAULT
	 * @throws InvalidKeyException In case invalid key is provided.
	 */
	public SecretKey decryptVaultEncryptionKey(byte[] cVaultEncryptionKey, SecretKey masterTransportKey, long ctr) throws InvalidKeyException {
		AESEncryptionUtils aes = new AESEncryptionUtils();
		KeyConversionUtils keyConversion = new KeyConversionUtils();
		KeyGenerator keyGen = new KeyGenerator();
		SecretKey vaultEncryptionTransportKey = keyGen.deriveSecretKey(masterTransportKey, ctr);
		byte[] zeroBytes = new byte[16];
		try {
			byte[] keyBytes = aes.decrypt(cVaultEncryptionKey, zeroBytes, vaultEncryptionTransportKey);
			return keyConversion.convertBytesToSharedSecretKey(keyBytes);
		} catch (IllegalBlockSizeException | BadPaddingException ex) {
			Logger.getLogger(PowerAuthClientVault.class.getName()).log(Level.SEVERE, null, ex);
		}
		return null;
	}
	
	/**
	 * Encrypts original device private key KEY_DEVICE_PRIVATE using the vault
	 * encryption key KEY_ENCRYPTION_VAULT.
	 * @param devicePrivateKey Device private key KEY_DEVICE_PRIVATE. 
	 * @param vaultEncryptionKey Vault encryption key KEY_ENCRYPTION_VAULT. 
	 * @return Encrypted private key.
	 * @throws InvalidKeyException In case invalid key is provided.
	 */
	public byte[] encryptDevicePrivateKey(PrivateKey devicePrivateKey, SecretKey vaultEncryptionKey) throws InvalidKeyException {
		try {
			AESEncryptionUtils aes = new AESEncryptionUtils();
			KeyConversionUtils keyConversion = new KeyConversionUtils();
			byte[] devicePrivateKeyBytes = keyConversion.convertPrivateKeyToBytes(devicePrivateKey);
			byte[] zeroBytes = new byte[16];
			return aes.encrypt(devicePrivateKeyBytes, zeroBytes, vaultEncryptionKey);
		} catch (IllegalBlockSizeException | BadPaddingException ex) {
			Logger.getLogger(PowerAuthClientVault.class.getName()).log(Level.SEVERE, null, ex);
		}
		return null;
	}
	
	/**
	 * Decrypts original device private key KEY_DEVICE_PRIVATE using the vault
	 * encryption key KEY_ENCRYPTION_VAULT.
	 * @param cDevicePrivateKey Encrypted device private key KEY_DEVICE_PRIVATE. 
	 * @param vaultEncryptionKey Vault encryption key KEY_ENCRYPTION_VAULT. 
	 * @return Original private key.
	 * @throws InvalidKeyException In case invalid key is provided.
	 */
	public PrivateKey decryptDevicePrivateKey(byte[] cDevicePrivateKey, SecretKey vaultEncryptionKey) throws InvalidKeyException {
		AESEncryptionUtils aes = new AESEncryptionUtils();
		KeyConversionUtils keyConversion = new KeyConversionUtils();
		byte[] zeroBytes = new byte[16];
		try {
			byte[] keyBytes = aes.decrypt(cDevicePrivateKey, zeroBytes, vaultEncryptionKey);
			return keyConversion.convertBytesToPrivateKey(keyBytes);
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException ex) {
			Logger.getLogger(PowerAuthClientVault.class.getName()).log(Level.SEVERE, null, ex);
		}
		return null;
	}

}
