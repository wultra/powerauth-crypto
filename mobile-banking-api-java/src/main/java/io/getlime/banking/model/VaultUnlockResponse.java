package io.getlime.banking.model;

public class VaultUnlockResponse {
	
	private String activationId;
	private String cVaultEncryptionKey;
	
	public String getActivationId() {
		return activationId;
	}
	
	public void setActivationId(String activationId) {
		this.activationId = activationId;
	}
	
	public String getcVaultEncryptionKey() {
		return cVaultEncryptionKey;
	}
	
	public void setcVaultEncryptionKey(String cVaultEncryptionKey) {
		this.cVaultEncryptionKey = cVaultEncryptionKey;
	}

}
