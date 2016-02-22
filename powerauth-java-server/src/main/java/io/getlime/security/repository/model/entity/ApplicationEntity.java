package io.getlime.security.repository.model.entity;

import java.io.Serializable;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;

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
	
	public ApplicationEntity() { }
	
	public ApplicationEntity(Long id, String name, List<ApplicationVersionEntity> versions) {
		super();
		this.id = id;
		this.name = name;
		this.versions = versions;
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

}
