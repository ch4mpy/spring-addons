/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.c4_soft.springaddons.test.security.support.jwt;

import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimAccessor;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.StandardClaimAccessor;
import org.springframework.util.StringUtils;

import com.c4_soft.oauth2.ModifiableClaimSet;

/**
 * https://openid.net/specs/openid-connect-core-1_0.html
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OidcIdClaimSetBuilder extends ModifiableClaimSet implements IdTokenClaimAccessor, StandardClaimAccessor {

	private static final long serialVersionUID = 8050195176203128543L;

	@Override
	public Map<String, Object> getClaims() {
		return this;
	}

	public OidcIdToken build(String tokenValue) {
		return new OidcIdToken(tokenValue, this.getIssuedAt(), this.getExpiresAt(), Collections.unmodifiableMap(this));
	}

	public OidcIdClaimSetBuilder issuer(URL issuer) {
		return setIfNonEmpty(IdTokenClaimNames.ISS, issuer.toString());
	}

	public OidcIdClaimSetBuilder subject(String subject) {
		return setIfNonEmpty(IdTokenClaimNames.SUB, subject);
	}

	public OidcIdClaimSetBuilder audience(List<String> audience) {
		return setIfNonEmpty(IdTokenClaimNames.AUD, audience);
	}

	public OidcIdClaimSetBuilder expiresAt(Instant expiresAt) {
		return setIfNonEmpty(IdTokenClaimNames.EXP, expiresAt);
	}

	public OidcIdClaimSetBuilder issuedAt(Instant issuedAt) {
		return setIfNonEmpty(IdTokenClaimNames.IAT, issuedAt);
	}

	public OidcIdClaimSetBuilder authTime(Instant authTime) {
		return setIfNonEmpty(IdTokenClaimNames.AUTH_TIME, authTime);
	}

	public OidcIdClaimSetBuilder nonce(String nonce) {
		return setIfNonEmpty(IdTokenClaimNames.NONCE, nonce);
	}

	public OidcIdClaimSetBuilder acr(String acr) {
		return setIfNonEmpty(IdTokenClaimNames.ACR, acr);
	}

	public OidcIdClaimSetBuilder amr(List<String> amr) {
		return setIfNonEmpty(IdTokenClaimNames.AMR, amr);
	}

	public OidcIdClaimSetBuilder azp(String azp) {
		return setIfNonEmpty(IdTokenClaimNames.AZP, azp);
	}

	public OidcIdClaimSetBuilder name(String value) {
		return setIfNonEmpty("name", value);
	}

	public OidcIdClaimSetBuilder givenName(String value) {
		return setIfNonEmpty("given_name", value);
	}

	public OidcIdClaimSetBuilder familyName(String value) {
		return setIfNonEmpty("family_name", value);
	}

	public OidcIdClaimSetBuilder middle_name(String value) {
		return setIfNonEmpty("middleName", value);
	}

	public OidcIdClaimSetBuilder nickname(String value) {
		return setIfNonEmpty("nickname", value);
	}

	public OidcIdClaimSetBuilder preferredUsername(String value) {
		return setIfNonEmpty("preferred_username", value);
	}

	public OidcIdClaimSetBuilder profile(String value) {
		return setIfNonEmpty("profile", value);
	}

	public OidcIdClaimSetBuilder picture(String value) {
		return setIfNonEmpty("picture", value);
	}

	public OidcIdClaimSetBuilder website(String value) {
		return setIfNonEmpty("website", value);
	}

	public OidcIdClaimSetBuilder email(String value) {
		return setIfNonEmpty("email", value);
	}

	public OidcIdClaimSetBuilder emailVerified(String value) {
		return setIfNonEmpty("email_verified", value);
	}

	public OidcIdClaimSetBuilder gender(String value) {
		return setIfNonEmpty("gender", value);
	}

	public OidcIdClaimSetBuilder birthdate(String value) {
		return setIfNonEmpty("birthdate", value);
	}

	public OidcIdClaimSetBuilder zoneinfo(String value) {
		return setIfNonEmpty("zoneinfo", value);
	}

	public OidcIdClaimSetBuilder locale(String value) {
		return setIfNonEmpty("locale", value);
	}

	public OidcIdClaimSetBuilder phoneNumber(String value) {
		return setIfNonEmpty("phone_number", value);
	}

	public OidcIdClaimSetBuilder phoneNumberVerified(Boolean value) {
		return setIfNonEmpty("phone_number_verified", value);
	}

	public OidcIdClaimSetBuilder address(AddressClaim value) {
		if (value == null) {
			this.remove("address");
		} else {
			this.put("address", value);
		}
		return this;
	}

	public OidcIdClaimSetBuilder updated_at(Instant value) {
		return setIfNonEmpty("", value);
	}

	private OidcIdClaimSetBuilder setIfNonEmpty(String claimName, String claimValue) {
		if (StringUtils.isEmpty(claimValue)) {
			this.remove(claimName);
		} else {
			this.put(claimName, claimValue);
		}
		return this;
	}

	private OidcIdClaimSetBuilder setIfNonEmpty(String claimName, Collection<String> claimValue) {
		if (claimValue == null || claimValue.size() == 0) {
			this.remove(claimName);
		} else if (claimValue.size() == 0) {
			this.setIfNonEmpty(claimName, claimValue.iterator().next());
		} else {
			this.put(claimName, claimValue);
		}
		return this;
	}

	private OidcIdClaimSetBuilder setIfNonEmpty(String claimName, Instant claimValue) {
		if (claimValue == null) {
			this.remove(claimName);
		} else {
			this.put(claimName, claimValue.getEpochSecond());
		}
		return this;
	}

	private OidcIdClaimSetBuilder setIfNonEmpty(String claimName, Boolean claimValue) {
		if (claimValue == null) {
			this.remove(claimName);
		} else {
			this.put(claimName, claimValue);
		}
		return this;
	}

	public static final class AddressClaim extends ModifiableClaimSet {
		private static final long serialVersionUID = 28800769851008900L;

		public AddressClaim formatted(String value) {
			return setIfNonEmpty("formatted", value);
		}

		public AddressClaim street_address(String value) {
			return setIfNonEmpty("street_address", value);
		}

		public AddressClaim locality(String value) {
			return setIfNonEmpty("locality", value);
		}

		public AddressClaim region(String value) {
			return setIfNonEmpty("region", value);
		}

		public AddressClaim postal_code(String value) {
			return setIfNonEmpty("postal_code", value);
		}

		public AddressClaim country(String value) {
			return setIfNonEmpty("country", value);
		}

		private AddressClaim setIfNonEmpty(String claimName, String claimValue) {
			if (StringUtils.isEmpty(claimValue)) {
				this.remove(claimName);
			} else {
				this.put(claimName, claimValue);
			}
			return this;
		}
	}
}
