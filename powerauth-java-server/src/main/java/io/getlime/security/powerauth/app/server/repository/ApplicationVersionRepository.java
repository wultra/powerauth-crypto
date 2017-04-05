/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.getlime.security.powerauth.app.server.repository;

import io.getlime.security.powerauth.app.server.repository.model.entity.ApplicationVersionEntity;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

/**
 * Database repository for access to application versions.
 *
 * @author Petr Dvorak
 */
public interface ApplicationVersionRepository extends CrudRepository<ApplicationVersionEntity, Long> {

    /**
     * Get all versions for given application.
     *
     * @param applicationId Application ID
     * @return List of versions
     */
    List<ApplicationVersionEntity> findByApplicationId(Long applicationId);

    /**
     * Find version by application key.
     *
     * @param applicationKey Application key.
     * @return Version with given application key.
     */
    ApplicationVersionEntity findByApplicationKey(String applicationKey);

}
