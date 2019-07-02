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
package com.c4_soft.springaddons.sample.e2e.dto;

import java.io.Serializable;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TokenResponse implements Serializable {
	private static final long serialVersionUID = 1696459882854033621L;

	@JsonProperty(value = "access_token")
	private String accessToken;

	@JsonProperty(value = "refresh_token")
	private String refreshToken;

	@JsonProperty(value = "token_type")
	private String tokenType;

	@JsonProperty(value = "expires_in")
	private Integer expiresIn;

	@JsonProperty(value = "scope")
	private String scope;

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public Integer getExpiresIn() {
		return expiresIn;
	}

	public void setExpiresIn(Integer expiresIn) {
		this.expiresIn = expiresIn;
	}

	public String getScope() {
		return scope;
	}

	public void setScope(String scope) {
		this.scope = scope;
	}

	@Override
	public int hashCode() {
		return Objects.hash(accessToken, expiresIn, refreshToken, scope, tokenType);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) return true;
		if (obj == null) return false;
		if (getClass() != obj.getClass()) return false;
		TokenResponse other = (TokenResponse) obj;
		return Objects.equals(accessToken, other.accessToken) && Objects.equals(expiresIn, other.expiresIn)
				&& Objects.equals(refreshToken, other.refreshToken) && Objects.equals(scope, other.scope)
				&& Objects.equals(tokenType, other.tokenType);
	}

}
