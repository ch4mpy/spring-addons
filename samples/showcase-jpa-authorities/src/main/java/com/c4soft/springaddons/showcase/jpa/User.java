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
package com.c4soft.springaddons.showcase.jpa;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.OneToMany;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
@Entity
public class User implements Serializable {
	private static final long serialVersionUID = 5233897654235486208L;

	@Id
	private String subject;

	@OneToMany
	private final Set<UserAuthority> authorities;

	public User(String subject) {
		this.subject = subject;
		this.authorities = new HashSet<>();
	}

	User() {
		this(null);
	}

	public String getSubject() {
		return subject;
	}

	void setId(String subject) {
		this.subject = subject;
	}

	public Set<GrantedAuthority> getAuthorities() {
		return this.authorities.stream()
				.map(UserAuthority::getAuthority)
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
	}

	public User setAuthorities(Stream<GrantedAuthority> authorities) {
		this.authorities.clear();
		this.authorities.addAll(authorities
				.map(authority -> new UserAuthority(this, authority.getAuthority()))
				.collect(Collectors.toSet()));
		return this;
	}

	public User setAuthorities(Collection<GrantedAuthority> authorities) {
		return setAuthorities(authorities.stream());
	}

	public User setAuthorities(String... authorities) {
		return setAuthorities(Stream.of(authorities).map(SimpleGrantedAuthority::new));
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((authorities == null) ? 0 : authorities.hashCode());
		result = prime * result + ((subject == null) ? 0 : subject.hashCode());
		return result;
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
		final User other = (User) obj;
		if (authorities == null) {
			if (other.authorities != null) {
				return false;
			}
		} else if (!authorities.equals(other.authorities)) {
			return false;
		}
		if (subject == null) {
			if (other.subject != null) {
				return false;
			}
		} else if (!subject.equals(other.subject)) {
			return false;
		}
		return true;
	}

}
