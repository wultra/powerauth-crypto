package io.getlime.security.service.behavior;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.google.common.io.BaseEncoding;

import io.getlime.security.powerauth.CreateApplicationResponse;
import io.getlime.security.powerauth.CreateApplicationVersionResponse;
import io.getlime.security.powerauth.GetApplicationDetailResponse;
import io.getlime.security.powerauth.GetApplicationListResponse;
import io.getlime.security.powerauth.SupportApplicationVersionResponse;
import io.getlime.security.powerauth.UnsupportApplicationVersionResponse;
import io.getlime.security.powerauth.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.lib.provider.CryptoProviderUtil;
import io.getlime.security.repository.ApplicationRepository;
import io.getlime.security.repository.ApplicationVersionRepository;
import io.getlime.security.repository.MasterKeyPairRepository;
import io.getlime.security.repository.model.entity.ApplicationEntity;
import io.getlime.security.repository.model.entity.ApplicationVersionEntity;
import io.getlime.security.repository.model.entity.MasterKeyPairEntity;

@Component
public class ApplicationServiceBehavior {

	@Autowired
	private ApplicationRepository applicationRepository;
	
	@Autowired
	private ApplicationVersionRepository applicationVersionRepository;
	
	@Autowired
	private MasterKeyPairRepository masterKeyPairRepository;

	public GetApplicationDetailResponse getApplicationDetail(Long applicationId) {

		ApplicationEntity application = applicationRepository.findOne(applicationId);

		GetApplicationDetailResponse response = new GetApplicationDetailResponse();
		response.setApplicationId(application.getId());
		response.setApplicationName(application.getName());
		response.setMasterPublicKey(masterKeyPairRepository.findFirstByApplicationIdOrderByTimestampCreatedDesc(application.getId()).getMasterKeyPublicBase64());

		List<ApplicationVersionEntity> versions = applicationVersionRepository.findByApplicationId(application.getId());
		for (ApplicationVersionEntity version : versions) {

			GetApplicationDetailResponse.Versions ver = new GetApplicationDetailResponse.Versions();
			ver.setApplicationVersionId(version.getId());
			ver.setApplicationKey(version.getApplicationKey());
			ver.setApplicationSecret(version.getApplicationSecret());
			ver.setApplicationVersionName(version.getName());
			ver.setSupported(version.getSupported());

			response.getVersions().add(ver);
		}

		return response;
	}

	public GetApplicationListResponse getApplicationList() {

		Iterable<ApplicationEntity> result = applicationRepository.findAll();

		GetApplicationListResponse response = new GetApplicationListResponse();

		for (Iterator<ApplicationEntity> iterator = result.iterator(); iterator.hasNext();) {
			ApplicationEntity application = (ApplicationEntity) iterator.next();
			GetApplicationListResponse.Applications app = new GetApplicationListResponse.Applications();
			app.setId(application.getId());
			app.setApplicationName(application.getName());
			response.getApplications().add(app);
		}

		return response;
	}
	
	public CreateApplicationResponse createApplication(String name, CryptoProviderUtil keyConversionUtilities) {
		
		ApplicationEntity application = new ApplicationEntity();
		application.setName(name);
		application = applicationRepository.save(application);
		
		KeyGenerator keyGen = new KeyGenerator();
		KeyPair kp = keyGen.generateKeyPair();
		PrivateKey privateKey = kp.getPrivate();
		PublicKey publicKey = kp.getPublic();
		
		// Generate the default master key pair
		MasterKeyPairEntity keyPair = new MasterKeyPairEntity();
		keyPair.setApplication(application);
		keyPair.setMasterKeyPrivateBase64(BaseEncoding.base64().encode(keyConversionUtilities.convertPrivateKeyToBytes(privateKey)));
		keyPair.setMasterKeyPublicBase64(BaseEncoding.base64().encode(keyConversionUtilities.convertPublicKeyToBytes(publicKey)));
		keyPair.setTimestampCreated(new Date());
		keyPair.setName(name + " Default Keypair");
		masterKeyPairRepository.save(keyPair);
		
		// Create the default application version
		byte[] applicationKeyBytes = keyGen.generateRandomBytes(16);
		byte[] applicationSecretBytes = keyGen.generateRandomBytes(16);
		ApplicationVersionEntity version = new ApplicationVersionEntity();
		version.setApplication(application);
		version.setName("default");
		version.setSupported(true);
		version.setApplicationKey(BaseEncoding.base64().encode(applicationKeyBytes));
		version.setApplicationSecret(BaseEncoding.base64().encode(applicationSecretBytes));
		applicationVersionRepository.save(version);
		
		CreateApplicationResponse response = new CreateApplicationResponse();
		response.setApplicationId(application.getId());
		response.setApplicationName(application.getName());
		
		return response;
	}
	
	public CreateApplicationVersionResponse createApplicationVersion(Long applicationId, String versionName) {
		
		ApplicationEntity application = applicationRepository.findOne(applicationId);
		
		KeyGenerator keyGen = new KeyGenerator();
		byte[] applicationKeyBytes = keyGen.generateRandomBytes(16);
		byte[] applicationSecretBytes = keyGen.generateRandomBytes(16);
		
		ApplicationVersionEntity version = new ApplicationVersionEntity();
		version.setApplication(application);
		version.setName(versionName);
		version.setSupported(true);
		version.setApplicationKey(BaseEncoding.base64().encode(applicationKeyBytes));
		version.setApplicationSecret(BaseEncoding.base64().encode(applicationSecretBytes));
		version = applicationVersionRepository.save(version);
		
		CreateApplicationVersionResponse response = new CreateApplicationVersionResponse();
		response.setApplicationVersionId(version.getId());
		response.setApplicationVersionName(version.getName());
		response.setApplicationKey(version.getApplicationKey());
		response.setApplicationSecret(version.getApplicationSecret());
		response.setSupported(version.getSupported());
		
		return response;
	}
	
	public UnsupportApplicationVersionResponse unsupportApplicationVersion(Long versionId) {
		
		ApplicationVersionEntity version = applicationVersionRepository.findOne(versionId);
		version.setSupported(false);
		version = applicationVersionRepository.save(version);
		
		UnsupportApplicationVersionResponse response = new UnsupportApplicationVersionResponse();
		response.setApplicationVersionId(version.getId());
		response.setSupported(version.getSupported());
		
		return response;
	}
	
	public SupportApplicationVersionResponse supportApplicationVersion(Long versionId) {
		
		ApplicationVersionEntity version = applicationVersionRepository.findOne(versionId);
		version.setSupported(true);
		version = applicationVersionRepository.save(version);
		
		SupportApplicationVersionResponse response = new SupportApplicationVersionResponse();
		response.setApplicationVersionId(version.getId());
		response.setSupported(version.getSupported());
		
		return response;
	}

}
