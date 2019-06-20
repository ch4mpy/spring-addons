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
package com.c4soft.springaddons.sample.resource.jpa;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Embeddable;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
@Embeddable
public class UserAuthorityId implements Serializable {
	private static final long serialVersionUID = -7586573368559768273L;

	@Column(name = "user_subject", nullable = false)
	private String userSubject;

	@Column(nullable = false)
	private String authority;

	public UserAuthorityId(String userSubject, String authority) {
		super();
		this.userSubject = userSubject;
		this.authority = authority;
	}

	protected UserAuthorityId() {}

	public String getAuthority() {
		return authority;
	}

	public void setAuthority(String authority) {
		this.authority = authority;
	}

	public String getUserSubject() {
		return userSubject;
	}

	public void setUserSubject(String userSubject) {
		this.userSubject = userSubject;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((authority == null) ? 0 : authority.hashCode());
		result = prime * result + ((userSubject == null) ? 0 : userSubject.hashCode());
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
		final UserAuthorityId other = (UserAuthorityId) obj;
		if (authority == null) {
			if (other.authority != null) {
				return false;
			}
		} else if (!authority.equals(other.authority)) {
			return false;
		}
		if (userSubject == null) {
			if (other.userSubject != null) {
				return false;
			}
		} else if (!userSubject.equals(other.userSubject)) {
			return false;
		}
		return true;
	}
}
