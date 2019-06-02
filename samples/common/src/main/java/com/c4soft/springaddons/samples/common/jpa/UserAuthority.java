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
package com.c4soft.springaddons.samples.common.jpa;

import java.io.Serializable;

import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.ManyToOne;
import javax.persistence.MapsId;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
@Entity
public class UserAuthority implements Serializable {
	private static final long serialVersionUID = 856612234908842436L;

	@EmbeddedId
	private UserAuthorityId id;

	@ManyToOne
	@MapsId("userId")
	private User user;

	public UserAuthority(User user, String authority) {
		super();
		this.user = user;
		this.id = new UserAuthorityId(user.getSubject(), authority);
	}

	protected UserAuthority() {}

	protected UserAuthorityId getId() {
		return id;
	}

	protected void setId(UserAuthorityId id) {
		this.id = id;
	}

	public String getAuthority() {
		return id.getAuthority();
	}

	public User getUser() {
		return user;
	}

	protected void setUser(User user) {
		this.user = user;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((id == null) ? 0 : id.hashCode());
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
		final UserAuthority other = (UserAuthority) obj;
		if (id == null) {
			if (other.id != null) {
				return false;
			}
		} else if (!id.equals(other.id)) {
			return false;
		}
		return true;
	}

}
