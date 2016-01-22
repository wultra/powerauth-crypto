package io.getlime.security.powerauth.lib.provider;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKey;

public interface CryptoProviderUtil {
	
	/**
	 * Get the provider name, for example "BC" for Bouncy Castle.
	 * @return Name of the provider, for example "BC" for Boucy Castle.
	 */
	public String getProviderName();

	/**
	 * Converts an EC public key to a byte array by encoding Q point parameter.
	 *
	 * @param publicKey An EC public key to be converted.
	 * @return A byte array representation of the EC public key.
	 */
	public byte[] convertPublicKeyToBytes(PublicKey publicKey);

	/**
	 * Converts byte array to an EC public key, by decoding the Q point
	 * parameter.
	 *
	 * @param keyBytes Bytes to be converted to EC public key.
	 * @return An instance of the EC public key on success, or null on failure.
	 * @throws InvalidKeySpecException When provided bytes are not a correct key
	 * representation.
	 */
	public PublicKey convertBytesToPublicKey(byte[] keyBytes) throws InvalidKeySpecException;

	/**
	 * Converts an EC private key to bytes by encoding the D number parameter.
	 *
	 * @param privateKey An EC private key to be converted to bytes.
	 * @return A byte array containing the representation of the EC private key.
	 */
	public byte[] convertPrivateKeyToBytes(PrivateKey privateKey);

	/**
	 * Convert a byte array to an EC private key by decoding the D number
	 * parameter.
	 *
	 * @param keyBytes Bytes to be converted to the EC private key.
	 * @return An instance of EC private key decoded from the input bytes.
	 * @throws InvalidKeySpecException The provided key bytes are not a valid EC
	 * private key.
	 */
	public PrivateKey convertBytesToPrivateKey(byte[] keyBytes) throws InvalidKeySpecException;

	/**
	 * Converts a shared secret key (usually used for AES based operations) to a
	 * byte array.
	 *
	 * @param sharedSecretKey A shared key to be converted to bytes.
	 * @return A byte array representation of the shared secret key.
	 */
	public byte[] convertSharedSecretKeyToBytes(SecretKey sharedSecretKey);

	/**
	 * Converts a byte array to the secret shared key (usually used for AES
	 * based operations).
	 *
	 * @param bytesSecretKey Bytes representing the shared key.
	 * @return An instance of the secret key by decoding from provided bytes.
	 */
	public SecretKey convertBytesToSharedSecretKey(byte[] bytesSecretKey);

}
