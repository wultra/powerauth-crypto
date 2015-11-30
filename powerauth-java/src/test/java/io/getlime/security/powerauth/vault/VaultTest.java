package io.getlime.security.powerauth.vault;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import com.google.common.io.BaseEncoding;

import io.getlime.security.powerauth.client.vault.PowerAuthClientVault;
import io.getlime.security.powerauth.server.vault.PowerAuthServerVault;
import io.getlime.security.powerauth.lib.config.PowerAuthConstants;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.util.KeyConversionUtils;

import static org.junit.Assert.*;

public class VaultTest {
	
	@Before
    public void setUp() {
        // Add Bouncy Castle Security Provider
        Security.addProvider(new BouncyCastleProvider());
    }
	
	@Test
	public void testVault() throws Exception {
		
		System.out.println("# PowerAuth 2.0 Signature");
        System.out.println();

        // Prepare test data
        KeyGenerator keyGenerator = new KeyGenerator();
        PowerAuthClientVault clientVault = new PowerAuthClientVault();
        PowerAuthServerVault serverVault = new PowerAuthServerVault();

        // Generate fake server and device keys
        KeyPair deviceKeyPair = keyGenerator.generateKeyPair();
        KeyPair serverKeyPair = keyGenerator.generateKeyPair();
        
        // Deduce shared master secret keys
        SecretKey deviceMasterKey = keyGenerator.computeSharedKey(deviceKeyPair.getPrivate(), serverKeyPair.getPublic());
        SecretKey serverMasterKey = keyGenerator.computeSharedKey(serverKeyPair.getPrivate(), deviceKeyPair.getPublic());
        assertEquals(deviceMasterKey, serverMasterKey);
        
        System.out.println("## Master Secret Key: " + BaseEncoding.base64().encode(new KeyConversionUtils().convertSharedSecretKeyToBytes(deviceMasterKey)));
        
        // Deduce client vault encryption key and client / server master transport key
        SecretKey clientVaultEncryptionKey = clientVault.deriveVaultEncryptionKey(deviceMasterKey);
        System.out.println("## Vault Encryption Key: " + BaseEncoding.base64().encode(new KeyConversionUtils().convertSharedSecretKeyToBytes(clientVaultEncryptionKey)));
        
        SecretKey clientTransportKey = keyGenerator.deriveSecretKey(deviceMasterKey, PowerAuthConstants.KEY_DERIVED.TRANSPORT);
        SecretKey serverTransportKey = keyGenerator.deriveSecretKey(serverMasterKey, PowerAuthConstants.KEY_DERIVED.TRANSPORT);
        assertEquals(clientTransportKey, serverTransportKey);
        System.out.println("## Master Transport Key: " + BaseEncoding.base64().encode(new KeyConversionUtils().convertSharedSecretKeyToBytes(clientTransportKey)));
        
        // Encrypt device private key
        byte[] cDevicePrivateKey = clientVault.encryptDevicePrivateKey(deviceKeyPair.getPrivate(), clientVaultEncryptionKey);
        
        // Get encrypted vault encryption key from the server
        for (long ctr = 0; ctr < 50; ctr++) {
        	
        	System.out.println();
            System.out.println("## Counter: " + ctr);
            
        	byte[] cVaultEncryptionKey = serverVault.encryptVaultEncryptionKey(serverKeyPair.getPrivate(), deviceKeyPair.getPublic(), ctr);
            System.out.println("## cVaultEncryptionKey: " + BaseEncoding.base64().encode(cVaultEncryptionKey));
            
        	SecretKey vaultEncryptionKeyLocal = clientVault.decryptVaultEncryptionKey(cVaultEncryptionKey, clientTransportKey, ctr);
        	assertEquals(clientVaultEncryptionKey, vaultEncryptionKeyLocal);
        	
        	PrivateKey devicePrivateKeyLocal = clientVault.decryptDevicePrivateKey(cDevicePrivateKey, vaultEncryptionKeyLocal);
        	assertEquals(deviceKeyPair.getPrivate(), devicePrivateKeyLocal);
        }
		
	}

}
