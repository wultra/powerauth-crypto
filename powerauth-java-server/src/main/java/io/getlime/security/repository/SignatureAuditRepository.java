package io.getlime.security.repository;

import java.util.Date;
import java.util.List;

import org.springframework.data.repository.CrudRepository;

import io.getlime.security.repository.model.entity.SignatureEntity;

public interface SignatureAuditRepository extends CrudRepository<SignatureEntity, Long> {
	
	List<SignatureEntity> findByActivation_UserIdAndTimestampCreatedBetween(String userId, Date startingDate, Date endingDate);

}
