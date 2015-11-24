/**
 * Copyright 2015 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.repository.model;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity(name = "pa_master_keypair")
public class MasterKeyPairEntity implements Serializable {

    private static final long serialVersionUID = 1507932260603647825L;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column
    private String name;

    @Column(nullable = false)
    private String masterKeyPrivateBase64;

    @Column(nullable = false)
    private String masterKeyPublicBase64;

    @Column(nullable = false)
    private Date timestampCreated;

    protected MasterKeyPairEntity() {
    }

    public MasterKeyPairEntity(Long id, String name, String masterKeyPrivateBase64, String masterKeyPublicBase64, Date timestampCreated) {
        this.id = id;
        this.name = name;
        this.masterKeyPrivateBase64 = masterKeyPrivateBase64;
        this.masterKeyPublicBase64 = masterKeyPublicBase64;
        this.timestampCreated = timestampCreated;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getMasterKeyPrivateBase64() {
        return masterKeyPrivateBase64;
    }

    public void setMasterKeyPrivateBase64(String masterKeyPrivateBase64) {
        this.masterKeyPrivateBase64 = masterKeyPrivateBase64;
    }

    public String getMasterKeyPublicBase64() {
        return masterKeyPublicBase64;
    }

    public void setMasterKeyPublicBase64(String masterKeyPublicBase64) {
        this.masterKeyPublicBase64 = masterKeyPublicBase64;
    }

    public Date getTimestampCreated() {
        return timestampCreated;
    }

    public void setTimestampCreated(Date timestampCreated) {
        this.timestampCreated = timestampCreated;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 37 * hash + Objects.hashCode(this.id);
        hash = 37 * hash + Objects.hashCode(this.name);
        hash = 37 * hash + Objects.hashCode(this.masterKeyPrivateBase64);
        hash = 37 * hash + Objects.hashCode(this.masterKeyPublicBase64);
        hash = 37 * hash + Objects.hashCode(this.timestampCreated);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final MasterKeyPairEntity other = (MasterKeyPairEntity) obj;
        if (!Objects.equals(this.name, other.name)) {
            return false;
        }
        if (!Objects.equals(this.id, other.id)) {
            return false;
        }
        if (!Objects.equals(this.masterKeyPrivateBase64, other.masterKeyPrivateBase64)) {
            return false;
        }
        if (!Objects.equals(this.masterKeyPublicBase64, other.masterKeyPublicBase64)) {
            return false;
        }
        if (!Objects.equals(this.timestampCreated, other.timestampCreated)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "MasterKeyPairEntity{"
                + "id=" + id
                + ", name=" + name
                + ", masterKeyPrivate=" + masterKeyPrivateBase64
                + ", masterKeyPublic=" + masterKeyPublicBase64
                + ", timestampCreated=" + timestampCreated
                + '}';
    }

}
