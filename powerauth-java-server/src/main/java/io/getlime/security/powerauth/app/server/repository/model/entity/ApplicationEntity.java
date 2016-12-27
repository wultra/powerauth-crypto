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

package io.getlime.security.powerauth.app.server.repository.model.entity;

import javax.persistence.*;
import java.io.Serializable;
import java.util.List;

/**
 * Entity class representing an application.
 *
 * @author Petr Dvorak
 */
@Entity(name = "pa_application")
public class ApplicationEntity implements Serializable {

    private static final long serialVersionUID = 1295434927785255417L;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id")
    private Long id;

    @Column(name = "name")
    private String name;

    @OneToMany(mappedBy = "application")
    private List<ApplicationVersionEntity> versions;

    /**
     * Default constructor
     */
    public ApplicationEntity() {
    }

    /**
     * Constructor for a new application
     *
     * @param id       Application ID
     * @param name     Application name
     * @param versions Collection of versions
     */
    public ApplicationEntity(Long id, String name, List<ApplicationVersionEntity> versions) {
        super();
        this.id = id;
        this.name = name;
        this.versions = versions;
    }

    /**
     * Get application ID
     *
     * @return Application ID
     */
    public Long getId() {
        return id;
    }

    /**
     * Set application ID
     *
     * @param id Application ID
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Get application name
     *
     * @return Application name
     */
    public String getName() {
        return name;
    }

    /**
     * Set application name
     *
     * @param name Application name
     */
    public void setName(String name) {
        this.name = name;
    }

}
