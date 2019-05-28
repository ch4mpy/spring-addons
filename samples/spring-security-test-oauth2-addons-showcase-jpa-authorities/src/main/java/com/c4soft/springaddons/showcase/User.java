/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.c4soft.springaddons.showcase;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
@Entity
@Table(name = "user")
public class User {

	@Id
	private UUID id;

	@Column
	private String nickName;

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, orphanRemoval = true)
	@JoinTable(name = "USER_AUTHORITIES", joinColumns = @JoinColumn(name = "user_id", nullable = false, updatable = false))
	private final Set<String> authorities;

	public User(UUID id, String nickName) {
		this.id = id;
		this.nickName = nickName;
		this.authorities = new HashSet<>();
	}

	public User(String nickName) {
		this(UUID.randomUUID(), nickName);
	}

	User() {
		this(null, null);
	}

	public UUID getId() {
		return id;
	}

	void setId(UUID id) {
		this.id = id;
	}

	public String getNickName() {
		return nickName;
	}

	public void setNickName(String nickName) {
		this.nickName = nickName;
	}

	public Set<GrantedAuthority> getAuthorities() {
		return this.authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
	}

	public void setAuthorities(Collection<GrantedAuthority> authorities) {
		this.authorities.clear();
		this.authorities.addAll(authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet()));
	}
}
