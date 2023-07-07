/*
 * Copyright 2020 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */
package com.c4_soft.springaddons.security.oauth2.test;

import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.StringUtils;

import com.c4_soft.springaddons.security.oidc.ModifiableClaimSet;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;

/**
 * https://openid.net/specs/openid-connect-core-1_0.html
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OpenidClaimSetBuilder extends ModifiableClaimSet {

	private static final long serialVersionUID = 8050195176203128543L;

	private String usernameClaim = StandardClaimNames.SUB;

	public OpenidClaimSetBuilder() {
	}

	public OpenidClaimSetBuilder(Map<String, Object> ptivateClaims) {
		super(ptivateClaims);
	}

	public OpenidClaimSet build() {
		return new OpenidClaimSet(this, usernameClaim);
	}

	public OpenidClaimSetBuilder usernameClaim(String usernameClaim) {
		this.usernameClaim = usernameClaim;
		return this;
	}

	public OpenidClaimSetBuilder acr(String acr) {
		return setIfNonEmpty(IdTokenClaimNames.ACR, acr);
	}

	public OpenidClaimSetBuilder amr(List<String> amr) {
		return setIfNonEmpty(IdTokenClaimNames.AMR, amr);
	}

	public OpenidClaimSetBuilder audience(List<String> audience) {
		return setIfNonEmpty(IdTokenClaimNames.AUD, audience);
	}

	public OpenidClaimSetBuilder authTime(Instant authTime) {
		return setIfNonEmpty(IdTokenClaimNames.AUTH_TIME, authTime);
	}

	public OpenidClaimSetBuilder azp(String azp) {
		return setIfNonEmpty(IdTokenClaimNames.AZP, azp);
	}

	public OpenidClaimSetBuilder expiresAt(Instant expiresAt) {
		return setIfNonEmpty(IdTokenClaimNames.EXP, expiresAt);
	}

	public OpenidClaimSetBuilder issuedAt(Instant issuedAt) {
		return setIfNonEmpty(IdTokenClaimNames.IAT, issuedAt);
	}

	public OpenidClaimSetBuilder jwtId(String jti) {
		return setIfNonEmpty(JwtClaimNames.JTI, jti);
	}

	public OpenidClaimSetBuilder issuer(URL issuer) {
		return setIfNonEmpty(IdTokenClaimNames.ISS, issuer.toString());
	}

	public OpenidClaimSetBuilder nonce(String nonce) {
		return setIfNonEmpty(IdTokenClaimNames.NONCE, nonce);
	}

	public OpenidClaimSetBuilder notBefore(Instant nbf) {
		return setIfNonEmpty(JwtClaimNames.NBF, nbf);
	}

	public OpenidClaimSetBuilder accessTokenHash(String atHash) {
		return setIfNonEmpty(IdTokenClaimNames.AT_HASH, atHash);
	}

	public OpenidClaimSetBuilder authorizationCodeHash(String cHash) {
		return setIfNonEmpty(IdTokenClaimNames.C_HASH, cHash);
	}

	public OpenidClaimSetBuilder sessionState(String sessionState) {
		return setIfNonEmpty("session_state", sessionState);
	}

	public OpenidClaimSetBuilder subject(String subject) {
		return setIfNonEmpty(IdTokenClaimNames.SUB, subject);
	}

	public OpenidClaimSetBuilder name(String value) {
		return setIfNonEmpty(StandardClaimNames.NAME, value);
	}

	public OpenidClaimSetBuilder givenName(String value) {
		return setIfNonEmpty(StandardClaimNames.GIVEN_NAME, value);
	}

	public OpenidClaimSetBuilder familyName(String value) {
		return setIfNonEmpty(StandardClaimNames.FAMILY_NAME, value);
	}

	public OpenidClaimSetBuilder middleName(String value) {
		return setIfNonEmpty(StandardClaimNames.MIDDLE_NAME, value);
	}

	public OpenidClaimSetBuilder nickname(String value) {
		return setIfNonEmpty(StandardClaimNames.NICKNAME, value);
	}

	public OpenidClaimSetBuilder preferredUsername(String value) {
		return setIfNonEmpty(StandardClaimNames.PREFERRED_USERNAME, value);
	}

	public OpenidClaimSetBuilder profile(String value) {
		return setIfNonEmpty(StandardClaimNames.PROFILE, value);
	}

	public OpenidClaimSetBuilder picture(String value) {
		return setIfNonEmpty(StandardClaimNames.PICTURE, value);
	}

	public OpenidClaimSetBuilder website(String value) {
		return setIfNonEmpty(StandardClaimNames.WEBSITE, value);
	}

	public OpenidClaimSetBuilder email(String value) {
		return setIfNonEmpty(StandardClaimNames.EMAIL, value);
	}

	public OpenidClaimSetBuilder emailVerified(Boolean value) {
		return setIfNonEmpty(StandardClaimNames.EMAIL_VERIFIED, value);
	}

	public OpenidClaimSetBuilder gender(String value) {
		return setIfNonEmpty(StandardClaimNames.GENDER, value);
	}

	public OpenidClaimSetBuilder birthdate(String value) {
		return setIfNonEmpty(StandardClaimNames.BIRTHDATE, value);
	}

	public OpenidClaimSetBuilder zoneinfo(String value) {
		return setIfNonEmpty(StandardClaimNames.ZONEINFO, value);
	}

	public OpenidClaimSetBuilder locale(String value) {
		return setIfNonEmpty(StandardClaimNames.LOCALE, value);
	}

	public OpenidClaimSetBuilder phoneNumber(String value) {
		return setIfNonEmpty(StandardClaimNames.PHONE_NUMBER, value);
	}

	public OpenidClaimSetBuilder phoneNumberVerified(Boolean value) {
		return setIfNonEmpty(StandardClaimNames.PHONE_NUMBER_VERIFIED, value);
	}

	public OpenidClaimSetBuilder address(AddressClaim value) {
		if (value == null) {
			this.remove("address");
		} else {
			this.put("address", value);
		}
		return this;
	}

	public OpenidClaimSetBuilder claims(Map<String, Object> claims) {
		this.putAll(claims);
		return this;
	}

	public OpenidClaimSetBuilder privateClaims(Map<String, Object> claims) {
		return this.claims(claims);
	}

	public OpenidClaimSetBuilder otherClaims(Map<String, Object> claims) {
		return this.claims(claims);
	}

	public OpenidClaimSetBuilder updatedAt(Instant value) {
		return setIfNonEmpty("", value);
	}

	protected OpenidClaimSetBuilder setIfNonEmpty(String claimName, String claimValue) {
		if (StringUtils.hasText(claimValue)) {
			this.put(claimName, claimValue);
		} else {
			this.remove(claimName);
		}
		return this;
	}

	protected OpenidClaimSetBuilder setIfNonEmpty(String claimName, Collection<String> claimValue) {
		if (claimValue == null || claimValue.isEmpty()) {
			this.remove(claimName);
		} else if (claimValue.isEmpty()) {
			this.setIfNonEmpty(claimName, claimValue.iterator().next());
		} else {
			this.put(claimName, claimValue);
		}
		return this;
	}

	protected OpenidClaimSetBuilder setIfNonEmpty(String claimName, Instant claimValue) {
		if (claimValue == null) {
			this.remove(claimName);
		} else {
			this.put(claimName, claimValue.getEpochSecond());
		}
		return this;
	}

	protected OpenidClaimSetBuilder setIfNonEmpty(String claimName, Boolean claimValue) {
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
			if (StringUtils.hasText(claimValue)) {
				this.put(claimName, claimValue);
			} else {
				this.remove(claimName);
			}
			return this;
		}
	}
}
