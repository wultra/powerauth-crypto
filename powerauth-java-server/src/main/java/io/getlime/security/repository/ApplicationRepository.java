package io.getlime.security.repository;

import org.springframework.data.repository.CrudRepository;

import io.getlime.security.repository.model.entity.ApplicationEntity;

public interface ApplicationRepository extends CrudRepository<ApplicationEntity, Long> {

	
}
