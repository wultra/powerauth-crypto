package io.getlime.security.service.behavior;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.lib.provider.CryptoProviderUtil;
import io.getlime.security.powerauth.lib.util.SignatureUtils;
import io.getlime.security.repository.ActivationRepository;
import io.getlime.security.repository.model.entity.ActivationRecordEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

/**
 * Behavior class implementing the asymmetric (ECDSA) signature validation related processes. The
 * class separates the logic from the main service class.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Component
public class AsymmetricSignatureServiceBehavior {

    private ActivationRepository activationRepository;
    private SignatureUtils signatureUtils = new SignatureUtils();

    @Autowired
    public AsymmetricSignatureServiceBehavior(ActivationRepository activationRepository) {
        this.activationRepository = activationRepository;
    }

    /**
     * Validate ECDSA signature for given data using public key associated with given activation ID.
     * @param activationId Activation ID to be used for device public key lookup.
     * @param data Data that were signed, in Base64 format.
     * @param signature Provided signature to be verified, in Base64 format.
     * @param keyConversionUtilities Key converter provided by the client code.
     * @return True in case signature validates for given data with provided public key, false otherwise.
     * @throws InvalidKeySpecException In case public key was corrupt.
     * @throws SignatureException In case it was not possible to validate the signature.
     * @throws InvalidKeyException In case public key was corrupt.
     */
    public boolean verifyECDSASignature(String activationId, String data, String signature, CryptoProviderUtil keyConversionUtilities) throws InvalidKeySpecException, SignatureException, InvalidKeyException {
        final ActivationRecordEntity activation = activationRepository.findFirstByActivationId(activationId);
        byte[] devicePublicKeyData = BaseEncoding.base64().decode(activation.getDevicePublicKeyBase64());
        PublicKey devicePublicKey = keyConversionUtilities.convertBytesToPublicKey(devicePublicKeyData);
        return signatureUtils.validateECDSASignature(BaseEncoding.base64().decode(data), BaseEncoding.base64().decode(signature), devicePublicKey);
    }

}
