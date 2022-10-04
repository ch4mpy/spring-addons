/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken_jpa_authorities;

import java.io.Serializable;

import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import lombok.Data;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
@Entity
@Data
public class UserAuthority implements Serializable {
	private static final long serialVersionUID = 856612234908842436L;

	@EmbeddedId
	private UserAuthorityId id;

	private String label;

	public UserAuthority(String userSubject, String authority, String label) {
		this.id = new UserAuthorityId(userSubject, authority);
		this.label = label;
	}

	protected UserAuthority() {
	}

	protected UserAuthorityId getId() {
		return id;
	}

	protected void setId(UserAuthorityId id) {
		this.id = id;
	}

	public String getAuthority() {
		return id.getAuthority();
	}

	public String getUserSubject() {
		return id.getUserSubject();
	}

}
