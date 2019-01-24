# List of Used Keys

Following keys are used in the PowerAuth cryptography scheme.

<table>
	<tr>
		<th>name</th>
		<th>created as</th>
		<th>purpose</th>
	</tr>
	<tr>
		<td><code>KEY_DEVICE_PRIVATE</code></td>
		<td>ECDH - private key</td>
		<td>Generated on client to allow construction of <code>KEY_MASTER_SECRET</code></td>
	</tr>
	<tr>
		<td><code>KEY_DEVICE_PUBLIC</code></td>
		<td>ECDH - public key</td>
		<td>Generated on client to allow construction of <code>KEY_MASTER_SECRET</code></td>
	</tr>
	<tr>
		<td><code>KEY_SERVER_PRIVATE</code></td>
		<td>ECDH - private key</td>
		<td>Generated on server to allow construction of <code>KEY_MASTER_SECRET</code></td>
	</tr>
	<tr>
		<td><code>KEY_SERVER_PUBLIC</code></td>
		<td>ECDH - public key</td>
		<td>Generated on server to allow construction of <code>KEY_MASTER_SECRET</code></td>
	</tr>
	<tr>
		<td><code>KEY_SERVER_MASTER_PRIVATE</code></td>
		<td>ECDH - private key</td>
		<td>Stored on server, used to assure authenticity of <code>KEY_DEVICE_PUBLIC</code> while transferring from server to client</td>
	</tr>
	<tr>
		<td><code>KEY_SERVER_MASTER_PUBLIC</code></td>
		<td>ECDH - public key</td>
		<td>Stored on client, used to assure authenticity of <code>KEY_DEVICE_PUBLIC</code> while transferring from server to client</td>
	</tr>
	<tr>
		<td><code>ACTIVATION_OTP</code></td>
		<td>Random OTP</td>
		<td>A 16b random OTP generated during activation, AES encrypts/decrypts data sent from server to client and vice versa</td>
	</tr>
	<tr>
		<td><code>KEY_MASTER_SECRET</code></td>
		<td>ECDH - pre-shared</td>
		<td>A key deduced using ECDH derivation, <code>KEY_MASTER_SECRET = ECDH.phase(KEY_DEVICE_PRIVATE,KEY_SERVER_PUBLIC) = ECDH.phase(KEY_SERVER_PRIVATE,KEY_DEVICE_PUBLIC)</code></td>
	</tr>
	<tr>
		<td><code>KEY_SIGNATURE_POSSESSION</code></td>
		<td>KDF derived key from <code>KEY_MASTER_SECRET</code></td>
		<td>A signing key associated with the possession, factor deduced using KDF derivation with <code>INDEX = 1</code>, <code>KEY_SIGNATURE_POSSESSION = KDF.expand(KEY_MASTER_SECRET, INDEX)</code>, used for subsequent request signing</td>
	</tr>
  <tr>
		<td><code>KEY_SIGNATURE_KNOWLEDGE</code></td>
		<td>KDF derived key from <code>KEY_MASTER_SECRET</code></td>
		<td>A key associated with the knowledge factor, deduced using KDF derivation with <code>INDEX = 2</code>, <code>KEY_SIGNATURE_KNOWLEDGE = KDF.expand(KEY_MASTER_SECRET, INDEX)</code>, used for subsequent request signing</td>
	</tr>
  <tr>
		<td><code>KEY_SIGNATURE_BIOMETRY</code></td>
		<td>KDF derived key from <code>KEY_MASTER_SECRET</code></td>
		<td>A key associated with the biometry factor, deduced using KDF derivation with <code>INDEX = 3</code>, <code>KEY_SIGNATURE_BIOMETRY = KDF.derive(KEY_MASTER_SECRET, INDEX)</code>, used for subsequent request signing</td>
	</tr>
	<tr>
		<td><code>KEY_TRANSPORT</code></td>
		<td>KDF derived key from <code>KEY_MASTER_SECRET</code></td>
		<td>A key deduced using KDF derivation with <code>INDEX = 1000</code>, <code>KEY_TRANSPORT = KDF.expand(KEY_MASTER_SECRET, INDEX)</code>, used for encrypted data transport. This key is used as master transport key for end-to-end encryption key derivation.</td>
	</tr>
	<tr>
		<td><code>KEY_TRANSPORT_PARTIAL</code></td>
		<td>KDF derived key from <code>KEY_TRANSPORT</code> using random 16B long <code>SESSION_INDEX</code> as index.</td>
		<td>A base key used for encrypted transport key derivation, deduced using KDF_INTERNAL derivation with <code>INDEX = SESSION_INDEX = Generator.randomBytes(16)</code>, <code>KEY_TRANSPORT_PARTIAL = KDF_INTERNAL.derive(KEY_TRANSPORT, INDEX)</code></td>
	</tr>
	<tr>
		<td><code>KEY_TRANSPORT_ENCRYPTION</code></td>
		<td>KDF derived key from <code>KEY_TRANSPORT_PARTIAL</code> using random 16B long <code>AD_HOC_INDEX</code> as index.</td>
		<td>A key used for particular data encryption, deduced using KDF_INTERNAL derivation with <code>INDEX = AD_HOC_INDEX = Generator.randomBytes(16)</code>, <code>KEY_TRANSPORT_ENCRYPTION = KDF_INTERNAL.derive(KEY_TRANSPORT_PARTIAL, INDEX)</code></td>
	</tr>
	<tr>
		<td><code>KEY_ENCRYPTION_VAULT</code></td>
		<td>KDF derived key from <code>KEY_MASTER_SECRET</code></td>
		<td>A key deduced using KDF derivation with <code>INDEX = 2000</code>, <code>KEY_ENCRYPTION_VAULT = KDF.expand(KEY_MASTER_SECRET, 2000)</code>, used for encrypting a vault that stores the secret data, such as <code>KEY_DEVICE_PRIVATE</code>.</td>
	</tr>
  	<tr>
		<td><code>KEY_ENCRYPTION_VAULT_TRANSPORT</code></td>
		<td>KDF derived key from <code>KEY_TRANSPORT</code> using <code>CTR</code> as index.</td>
		<td>A one-time key used for encrypted transport of the key vault encryption, deduced using KDF derivation with <code>INDEX = CTR</code>, <code>KEY_ENCRYPTION_VAULT_TRANSPORT = KDF.derive(KEY_TRANSPORT, INDEX)</code></td>
	</tr>
</table>
