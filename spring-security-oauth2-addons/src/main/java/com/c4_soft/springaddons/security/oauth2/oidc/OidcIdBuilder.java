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
import org.springframework.security.oauth2.core.oidc.StandardClaimAccessor;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.util.StringUtils;

import com.c4_soft.springaddons.security.oauth2.ModifiableClaimSet;

/**
 * https://openid.net/specs/openid-connect-core-1_0.html
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OidcIdBuilder extends ModifiableClaimSet implements IdTokenClaimAccessor, StandardClaimAccessor {

	private static final long serialVersionUID = 8050195176203128543L;

	public OidcIdBuilder() {
		super();
	}

	public OidcIdBuilder(Map<String, Object> other) {
		super(other);
	}

	@Override
	public Map<String, Object> getClaims() {
		return this;
	}

	public OidcId build() {
		return new OidcId(this);
	}

	public OidcIdBuilder issuer(URL issuer) {
		return setIfNonEmpty(IdTokenClaimNames.ISS, issuer.toString());
	}

	public OidcIdBuilder subject(String subject) {
		return setIfNonEmpty(IdTokenClaimNames.SUB, subject);
	}

	public OidcIdBuilder audience(List<String> audience) {
		return setIfNonEmpty(IdTokenClaimNames.AUD, audience);
	}

	public OidcIdBuilder expiresAt(Instant expiresAt) {
		return setIfNonEmpty(IdTokenClaimNames.EXP, expiresAt);
	}

	public OidcIdBuilder issuedAt(Instant issuedAt) {
		return setIfNonEmpty(IdTokenClaimNames.IAT, issuedAt);
	}

	public OidcIdBuilder authTime(Instant authTime) {
		return setIfNonEmpty(IdTokenClaimNames.AUTH_TIME, authTime);
	}

	public OidcIdBuilder nonce(String nonce) {
		return setIfNonEmpty(IdTokenClaimNames.NONCE, nonce);
	}

	public OidcIdBuilder acr(String acr) {
		return setIfNonEmpty(IdTokenClaimNames.ACR, acr);
	}

	public OidcIdBuilder amr(List<String> amr) {
		return setIfNonEmpty(IdTokenClaimNames.AMR, amr);
	}

	public OidcIdBuilder azp(String azp) {
		return setIfNonEmpty(IdTokenClaimNames.AZP, azp);
	}

	public OidcIdBuilder name(String value) {
		return setIfNonEmpty(StandardClaimNames.NAME, value);
	}

	public OidcIdBuilder givenName(String value) {
		return setIfNonEmpty(StandardClaimNames.GIVEN_NAME, value);
	}

	public OidcIdBuilder familyName(String value) {
		return setIfNonEmpty(StandardClaimNames.FAMILY_NAME, value);
	}

	public OidcIdBuilder middleName(String value) {
		return setIfNonEmpty(StandardClaimNames.MIDDLE_NAME, value);
	}

	public OidcIdBuilder nickname(String value) {
		return setIfNonEmpty(StandardClaimNames.NICKNAME, value);
	}

	public OidcIdBuilder preferredUsername(String value) {
		return setIfNonEmpty(StandardClaimNames.PREFERRED_USERNAME, value);
	}

	public OidcIdBuilder profile(String value) {
		return setIfNonEmpty(StandardClaimNames.PROFILE, value);
	}

	public OidcIdBuilder picture(String value) {
		return setIfNonEmpty(StandardClaimNames.PICTURE, value);
	}

	public OidcIdBuilder website(String value) {
		return setIfNonEmpty(StandardClaimNames.WEBSITE, value);
	}

	public OidcIdBuilder email(String value) {
		return setIfNonEmpty(StandardClaimNames.EMAIL, value);
	}

	public OidcIdBuilder emailVerified(Boolean value) {
		return setIfNonEmpty(StandardClaimNames.EMAIL_VERIFIED, value);
	}

	public OidcIdBuilder gender(String value) {
		return setIfNonEmpty(StandardClaimNames.GENDER, value);
	}

	public OidcIdBuilder birthdate(String value) {
		return setIfNonEmpty(StandardClaimNames.BIRTHDATE, value);
	}

	public OidcIdBuilder zoneinfo(String value) {
		return setIfNonEmpty(StandardClaimNames.ZONEINFO, value);
	}

	public OidcIdBuilder locale(String value) {
		return setIfNonEmpty(StandardClaimNames.LOCALE, value);
	}

	public OidcIdBuilder phoneNumber(String value) {
		return setIfNonEmpty(StandardClaimNames.PHONE_NUMBER, value);
	}

	public OidcIdBuilder phoneNumberVerified(Boolean value) {
		return setIfNonEmpty(StandardClaimNames.PHONE_NUMBER_VERIFIED, value);
	}

	public OidcIdBuilder address(AddressClaim value) {
		if (value == null) {
			this.remove("address");
		} else {
			this.put("address", value);
		}
		return this;
	}

	public OidcIdBuilder updatedAt(Instant value) {
		return setIfNonEmpty("", value);
	}

	private OidcIdBuilder setIfNonEmpty(String claimName, String claimValue) {
		if (StringUtils.isEmpty(claimValue)) {
			this.remove(claimName);
		} else {
			this.put(claimName, claimValue);
		}
		return this;
	}

	private OidcIdBuilder setIfNonEmpty(String claimName, Collection<String> claimValue) {
		if (claimValue == null || claimValue.size() == 0) {
			this.remove(claimName);
		} else if (claimValue.size() == 0) {
			this.setIfNonEmpty(claimName, claimValue.iterator().next());
		} else {
			this.put(claimName, claimValue);
		}
		return this;
	}

	private OidcIdBuilder setIfNonEmpty(String claimName, Instant claimValue) {
		if (claimValue == null) {
			this.remove(claimName);
		} else {
			this.put(claimName, claimValue.getEpochSecond());
		}
		return this;
	}

	private OidcIdBuilder setIfNonEmpty(String claimName, Boolean claimValue) {
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

		public AddressClaim streetAddress(String value) {
			return setIfNonEmpty("street_address", value);
		}

		public AddressClaim locality(String value) {
			return setIfNonEmpty("locality", value);
		}

		public AddressClaim region(String value) {
			return setIfNonEmpty("region", value);
		}

		public AddressClaim postalCode(String value) {
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
