package io.getlime.security.repository;

import io.getlime.security.repository.model.MasterKeyPairEntity;
import org.springframework.data.repository.CrudRepository;

public interface MasterKeyPairRepository extends CrudRepository<MasterKeyPairEntity, Long> {
    
    MasterKeyPairEntity findFirstByOrderByTimestampCreatedDesc();
    
}
