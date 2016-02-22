package io.getlime.security.repository;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import io.getlime.security.repository.model.entity.ApplicationVersionEntity;

public interface ApplicationVersionRepository extends CrudRepository<ApplicationVersionEntity, Long> {
	
	public List<ApplicationVersionEntity> findByApplicationId(Long applicationId);
	
	public ApplicationVersionEntity findByApplicationKey(String applicationKey);

}
