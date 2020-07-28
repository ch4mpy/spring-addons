/*
 * Copyright 2020 Jérôme Wacongne
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
package com.c4_soft.springaddons.security.oauth2.oidc;

import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimAccessor;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.util.StringUtils;

import com.c4_soft.springaddons.security.oauth2.ModifiableClaimSet;

/**
 * https://openid.net/specs/openid-connect-core-1_0.html
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class IdTokenBuilder<T extends IdTokenBuilder<T>> extends ModifiableClaimSet implements IdTokenClaimAccessor {

	private static final long serialVersionUID = -5154145006352851685L;

	public IdTokenBuilder() {
		super();
	}

	public IdTokenBuilder(Map<String, Object> other) {
		super(other);
	}

	@Override
	public Map<String, Object> getClaims() {
		return this;
	}

	public IdToken build() {
		return new IdToken(this);
	}

	public T issuer(URL issuer) {
		return setIfNonEmpty(IdTokenClaimNames.ISS, issuer.toString());
	}

	public T subject(String subject) {
		return setIfNonEmpty(IdTokenClaimNames.SUB, subject);
	}

	public T audience(List<String> audience) {
		return setIfNonEmpty(IdTokenClaimNames.AUD, audience);
	}

	public T expiresAt(Instant expiresAt) {
		return setIfNonEmpty(IdTokenClaimNames.EXP, expiresAt);
	}

	public T issuedAt(Instant issuedAt) {
		return setIfNonEmpty(IdTokenClaimNames.IAT, issuedAt);
	}

	public T authTime(Instant authTime) {
		return setIfNonEmpty(IdTokenClaimNames.AUTH_TIME, authTime);
	}

	public T nonce(String nonce) {
		return setIfNonEmpty(IdTokenClaimNames.NONCE, nonce);
	}

	public T acr(String acr) {
		return setIfNonEmpty(IdTokenClaimNames.ACR, acr);
	}

	public T amr(List<String> amr) {
		return setIfNonEmpty(IdTokenClaimNames.AMR, amr);
	}

	public T azp(String azp) {
		return setIfNonEmpty(IdTokenClaimNames.AZP, azp);
	}

	protected T setIfNonEmpty(String claimName, String claimValue) {
		if (StringUtils.isEmpty(claimValue)) {
			this.remove(claimName);
		} else {
			this.put(claimName, claimValue);
		}
		return downcast();
	}

	protected T setIfNonEmpty(String claimName, Collection<String> claimValue) {
		if (claimValue == null || claimValue.size() == 0) {
			this.remove(claimName);
		} else if (claimValue.size() == 0) {
			this.setIfNonEmpty(claimName, claimValue.iterator().next());
		} else {
			this.put(claimName, claimValue);
		}
		return downcast();
	}

	protected T setIfNonEmpty(String claimName, Instant claimValue) {
		if (claimValue == null) {
			this.remove(claimName);
		} else {
			this.put(claimName, claimValue.getEpochSecond());
		}
		return downcast();
	}

	protected T setIfNonEmpty(String claimName, Boolean claimValue) {
		if (claimValue == null) {
			this.remove(claimName);
		} else {
			this.put(claimName, claimValue);
		}
		return downcast();
	}

	@SuppressWarnings("unchecked")
	private T downcast() {
		return (T) this;
	}
}
