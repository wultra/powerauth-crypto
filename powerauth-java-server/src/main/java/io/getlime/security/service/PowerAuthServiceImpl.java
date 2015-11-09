package io.getlime.security.service;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.BlockActivationRequest;
import io.getlime.security.powerauth.BlockActivationResponse;
import io.getlime.security.powerauth.CommitActivationRequest;
import io.getlime.security.powerauth.CommitActivationResponse;
import io.getlime.security.powerauth.GetActivationListForUserRequest;
import io.getlime.security.powerauth.GetActivationListForUserResponse;
import io.getlime.security.powerauth.GetActivationStatusRequest;
import io.getlime.security.powerauth.GetActivationStatusResponse;
import io.getlime.security.powerauth.InitActivationRequest;
import io.getlime.security.powerauth.InitActivationResponse;
import io.getlime.security.powerauth.PrepareActivationRequest;
import io.getlime.security.powerauth.PrepareActivationResponse;
import io.getlime.security.powerauth.RemoveActivationRequest;
import io.getlime.security.powerauth.RemoveActivationResponse;
import io.getlime.security.powerauth.UnblockActivationRequest;
import io.getlime.security.powerauth.UnblockActivationResponse;
import io.getlime.security.powerauth.VerifySignatureRequest;
import io.getlime.security.powerauth.VerifySignatureResponse;
import io.getlime.security.powerauth.lib.util.KeyConversionUtils;
import io.getlime.security.powerauth.server.activation.PowerAuthServerActivation;
import io.getlime.security.repository.MasterKeyPairRepository;
import io.getlime.security.repository.PowerAuthRepository;
import io.getlime.security.repository.model.ActivationRecordEntity;
import io.getlime.security.repository.model.ActivationStatus;
import io.getlime.security.repository.model.MasterKeyPairEntity;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class PowerAuthServiceImpl implements PowerAuthService {

    @Autowired
    private PowerAuthRepository powerAuthRepository;
    
    @Autowired
    private MasterKeyPairRepository masterKeyPairRepository;

    private final PowerAuthServerActivation powerAuthServerActivation = new PowerAuthServerActivation();
    private final KeyConversionUtils keyConversionUtilities = new KeyConversionUtils();
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public InitActivationResponse initActivation(InitActivationRequest request) {

        try {
            
            // Generate timestamp in advance
            Long timestamp = (System.currentTimeMillis() / 1000L);

            // Fetch the latest master private key
            MasterKeyPairEntity masterKeyPair = masterKeyPairRepository.findFirstByOrderByTimestampCreatedDesc();
            byte[] masterPrivateKeyBytes = BaseEncoding.base64().decode(masterKeyPair.getMasterKeyPrivateBase64());
            PrivateKey masterPrivateKey = keyConversionUtilities.convertBytesToPrivateKey(masterPrivateKeyBytes);

            // Generate new activation data
            String activationId = powerAuthServerActivation.generateActivationId();
            String activationIdShort = powerAuthServerActivation.generateActivationIdShort();
            String activationOtp = powerAuthServerActivation.generateActivationOTP();
            byte[] activationSignature = powerAuthServerActivation.generateActivationSignature(activationIdShort, activationOtp, masterPrivateKey);
            String activationSignatureBase64 = BaseEncoding.base64().encode(activationSignature);
            KeyPair serverKeyPair = powerAuthServerActivation.generateServerKeyPair();

            ActivationRecordEntity activation = new ActivationRecordEntity(
                    activationId,
                    activationIdShort,
                    activationOtp,
                    request.getUserId(),
                    null,
                    keyConversionUtilities.convertPrivateKeyToBytes(serverKeyPair.getPrivate()),
                    keyConversionUtilities.convertPublicKeyToBytes(serverKeyPair.getPublic()),
                    null,
                    new Long(0),
                    new Long(0),
                    timestamp,
                    timestamp,
                    ActivationStatus.CREATED,
                    masterKeyPair
            );

            powerAuthRepository.save(activation);

            InitActivationResponse response = new InitActivationResponse();
            response.setActivationIdShort(activationIdShort);
            response.setUserId(request.getUserId());
            response.setActivationOTP(activationOtp);
            response.setActivationSignature(activationSignatureBase64);

            return response;
        } catch (InvalidKeySpecException | InvalidKeyException ex) {
            Logger.getLogger(PowerAuthServiceImpl.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    @Override
    public PrepareActivationResponse prepareActivation(PrepareActivationRequest request) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public CommitActivationResponse commitActivation(CommitActivationRequest request) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public GetActivationStatusResponse getActivationStatus(GetActivationStatusRequest request) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public RemoveActivationResponse removeActivation(RemoveActivationRequest request) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public GetActivationListForUserResponse getActivatioListForUser(GetActivationListForUserRequest request) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public VerifySignatureResponse verifySignature(VerifySignatureRequest request) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public BlockActivationResponse blockActivation(BlockActivationRequest request) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public UnblockActivationResponse unblockActivation(UnblockActivationRequest request) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
