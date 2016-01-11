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
package io.getlime.security.repository.model.entity;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;

import io.getlime.security.repository.model.ActivationStatus;
import io.getlime.security.repository.model.ActivationStatusConverter;

@Entity(name = "pa_signature_audit")
public class SignatureEntity implements Serializable {

	private static final long serialVersionUID = 1930424474990335368L;

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	@Column(name = "id")
	private Long id;

	@ManyToOne
	@JoinColumn(name = "activation_id", referencedColumnName = "activation_id", nullable = true, updatable = false)
	private ActivationRecordEntity activation;

	@Column(name = "activation_counter", nullable = false)
	private Long activationCounter;

	@Column(name = "activation_status", nullable = true)
	@Convert(converter = ActivationStatusConverter.class)
	private ActivationStatus activationStatus;

	@Column(name = "data_base64", updatable = false)
	private String dataBase64;

	@Column(name = "signature_type", nullable = false, updatable = false)
	private String signatureType;

	@Column(name = "signature", nullable = false, updatable = false)
	private String signature;

	@Column(name = "note", updatable = false)
	private String note;

	@Column(name = "valid", nullable = false, updatable = false)
	private Boolean valid;

	@Column(name = "timestamp_created", nullable = false)
	private Date timestampCreated;

	public SignatureEntity() {
	}

	public SignatureEntity(Long id, ActivationRecordEntity activation, Long activationCounter, ActivationStatus activationStatus, String dataBase64, String signatureType, String signature, String note, Boolean valid, Date timestampCreated) {
		super();
		this.id = id;
		this.activation = activation;
		this.activationCounter = activationCounter;
		this.activationStatus = activationStatus;
		this.dataBase64 = dataBase64;
		this.signatureType = signatureType;
		this.signature = signature;
		this.note = note;
		this.valid = valid;
		this.timestampCreated = timestampCreated;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public ActivationRecordEntity getActivation() {
		return activation;
	}

	public void setActivation(ActivationRecordEntity activation) {
		this.activation = activation;
	}

	public Long getActivationCounter() {
		return activationCounter;
	}

	public void setActivationCounter(Long activationCounter) {
		this.activationCounter = activationCounter;
	}

	public ActivationStatus getActivationStatus() {
		return activationStatus;
	}

	public void setActivationStatus(ActivationStatus activationStatus) {
		this.activationStatus = activationStatus;
	}

	public String getDataBase64() {
		return dataBase64;
	}

	public void setDataBase64(String dataBase64) {
		this.dataBase64 = dataBase64;
	}

	public String getNote() {
		return note;
	}

	public void setNote(String note) {
		this.note = note;
	}

	public String getSignatureType() {
		return signatureType;
	}

	public void setSignatureType(String signatureType) {
		this.signatureType = signatureType;
	}

	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public Boolean getValid() {
		return valid;
	}

	public void setValid(Boolean valid) {
		this.valid = valid;
	}

	public Date getTimestampCreated() {
		return timestampCreated;
	}

	public void setTimestampCreated(Date timestampCreated) {
		this.timestampCreated = timestampCreated;
	}

	@Override
	public int hashCode() {
		int hash = 7;
		hash = 23 * hash + Objects.hashCode(this.id);
		hash = 23 * hash + Objects.hashCode(this.activation);
		hash = 23 * hash + Objects.hashCode(this.activationCounter);
		hash = 23 * hash + Objects.hashCode(this.activationStatus);
		hash = 23 * hash + Objects.hashCode(this.dataBase64);
		hash = 23 * hash + Objects.hashCode(this.signatureType);
		hash = 23 * hash + Objects.hashCode(this.signature);
		hash = 23 * hash + Objects.hashCode(this.note);
		hash = 23 * hash + Objects.hashCode(this.valid);
		hash = 23 * hash + Objects.hashCode(this.timestampCreated);
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
		final SignatureEntity other = (SignatureEntity) obj;
		if (!Objects.equals(this.dataBase64, other.dataBase64)) {
			return false;
		}
		if (!Objects.equals(this.signatureType, other.signatureType)) {
			return false;
		}
		if (!Objects.equals(this.signature, other.signature)) {
			return false;
		}
		if (!Objects.equals(this.id, other.id)) {
			return false;
		}
		if (!Objects.equals(this.activation, other.activation)) {
			return false;
		}
		if (!Objects.equals(this.activationCounter, other.activationCounter)) {
			return false;
		}
		if (!Objects.equals(this.activationStatus, other.activationStatus)) {
			return false;
		}
		if (!Objects.equals(this.valid, other.valid)) {
			return false;
		}
		if (!Objects.equals(this.timestampCreated, other.timestampCreated)) {
			return false;
		}
		if (!Objects.equals(this.note, other.note)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "SignatureEntity{" + "id=" + id + ", activation=" + activation + ", activationCounter=" + activationCounter + ", activationStatus=" + activationStatus + ", dataBase64=" + dataBase64 + ", signatureType=" + signatureType + ", signature=" + signature + ", valid=" + valid + ", note=" + note + ", timestampCreated=" + timestampCreated + '}';
	}

}
