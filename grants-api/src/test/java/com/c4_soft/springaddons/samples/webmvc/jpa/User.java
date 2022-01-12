package com.c4_soft.springaddons.samples.webmvc.jpa;

import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.OneToMany;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
public class User {
	@Id
	@GeneratedValue
	private Long id;

	@Column(unique = true, nullable = false)
	private String subject;

	@OneToMany(cascade = CascadeType.ALL)
	private Set<Proxy> proxies;
}
