package io.getlime.push.repository;

import io.getlime.push.repository.model.PushMessageEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Repository interface used to access push message database.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Repository
public interface PushMessageRepository extends CrudRepository<PushMessageEntity, Long> {

    List<PushMessageEntity> findByStatus(PushMessageEntity.Status status);

}
