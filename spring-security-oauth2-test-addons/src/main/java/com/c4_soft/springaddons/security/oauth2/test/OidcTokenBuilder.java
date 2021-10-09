/*
 * Copyright 2020 Jérôme Wacongne
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

import com.c4_soft.springaddons.security.oauth2.ModifiableClaimSet;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;

/**
 * https://openid.net/specs/openid-connect-core-1_0.html
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OidcTokenBuilder extends ModifiableClaimSet {

	private static final long serialVersionUID = 8050195176203128543L;

	public OidcTokenBuilder() {
	}

	public OidcTokenBuilder(Map<String, Object> ptivateClaims) {
		super(ptivateClaims);
	}

	public OidcToken build() {
		return new OidcToken(this);
	}

	public OidcTokenBuilder acr(String acr) {
		return setIfNonEmpty(IdTokenClaimNames.ACR, acr);
	}

	public OidcTokenBuilder amr(List<String> amr) {
		return setIfNonEmpty(IdTokenClaimNames.AMR, amr);
	}

	public OidcTokenBuilder audience(List<String> audience) {
		return setIfNonEmpty(IdTokenClaimNames.AUD, audience);
	}

	public OidcTokenBuilder authTime(Instant authTime) {
		return setIfNonEmpty(IdTokenClaimNames.AUTH_TIME, authTime);
	}

	public OidcTokenBuilder azp(String azp) {
		return setIfNonEmpty(IdTokenClaimNames.AZP, azp);
	}

	public OidcTokenBuilder expiresAt(Instant expiresAt) {
		return setIfNonEmpty(IdTokenClaimNames.EXP, expiresAt);
	}

	public OidcTokenBuilder issuedAt(Instant issuedAt) {
		return setIfNonEmpty(IdTokenClaimNames.IAT, issuedAt);
	}

	public OidcTokenBuilder jwtId(String jti) {
		return setIfNonEmpty(JwtClaimNames.JTI, jti);
	}

	public OidcTokenBuilder issuer(URL issuer) {
		return setIfNonEmpty(IdTokenClaimNames.ISS, issuer.toString());
	}

	public OidcTokenBuilder nonce(String nonce) {
		return setIfNonEmpty(IdTokenClaimNames.NONCE, nonce);
	}

	public OidcTokenBuilder notBefore(Instant nbf) {
		return setIfNonEmpty(JwtClaimNames.NBF, nbf);
	}

	public OidcTokenBuilder accessTokenHash(String atHash) {
		return setIfNonEmpty(IdTokenClaimNames.AT_HASH, atHash);
	}

	public OidcTokenBuilder authorizationCodeHash(String cHash) {
		return setIfNonEmpty(IdTokenClaimNames.C_HASH, cHash);
	}

	public OidcTokenBuilder sessionState(String sessionState) {
		return setIfNonEmpty("session_state", sessionState);
	}

	public OidcTokenBuilder subject(String subject) {
		return setIfNonEmpty(IdTokenClaimNames.SUB, subject);
	}

	public OidcTokenBuilder name(String value) {
		return setIfNonEmpty(StandardClaimNames.NAME, value);
	}

	public OidcTokenBuilder givenName(String value) {
		return setIfNonEmpty(StandardClaimNames.GIVEN_NAME, value);
	}

	public OidcTokenBuilder familyName(String value) {
		return setIfNonEmpty(StandardClaimNames.FAMILY_NAME, value);
	}

	public OidcTokenBuilder middleName(String value) {
		return setIfNonEmpty(StandardClaimNames.MIDDLE_NAME, value);
	}

	public OidcTokenBuilder nickname(String value) {
		return setIfNonEmpty(StandardClaimNames.NICKNAME, value);
	}

	public OidcTokenBuilder preferredUsername(String value) {
		return setIfNonEmpty(StandardClaimNames.PREFERRED_USERNAME, value);
	}

	public OidcTokenBuilder profile(String value) {
		return setIfNonEmpty(StandardClaimNames.PROFILE, value);
	}

	public OidcTokenBuilder picture(String value) {
		return setIfNonEmpty(StandardClaimNames.PICTURE, value);
	}

	public OidcTokenBuilder website(String value) {
		return setIfNonEmpty(StandardClaimNames.WEBSITE, value);
	}

	public OidcTokenBuilder email(String value) {
		return setIfNonEmpty(StandardClaimNames.EMAIL, value);
	}

	public OidcTokenBuilder emailVerified(Boolean value) {
		return setIfNonEmpty(StandardClaimNames.EMAIL_VERIFIED, value);
	}

	public OidcTokenBuilder gender(String value) {
		return setIfNonEmpty(StandardClaimNames.GENDER, value);
	}

	public OidcTokenBuilder birthdate(String value) {
		return setIfNonEmpty(StandardClaimNames.BIRTHDATE, value);
	}

	public OidcTokenBuilder zoneinfo(String value) {
		return setIfNonEmpty(StandardClaimNames.ZONEINFO, value);
	}

	public OidcTokenBuilder locale(String value) {
		return setIfNonEmpty(StandardClaimNames.LOCALE, value);
	}

	public OidcTokenBuilder phoneNumber(String value) {
		return setIfNonEmpty(StandardClaimNames.PHONE_NUMBER, value);
	}

	public OidcTokenBuilder phoneNumberVerified(Boolean value) {
		return setIfNonEmpty(StandardClaimNames.PHONE_NUMBER_VERIFIED, value);
	}

	public OidcTokenBuilder address(AddressClaim value) {
		if (value == null) {
			this.remove("address");
		} else {
			this.put("address", value);
		}
		return this;
	}

	public OidcTokenBuilder claims(Map<String, Object> claims) {
		this.putAll(claims);
		return this;
	}

	public OidcTokenBuilder privateClaims(Map<String, Object> claims) {
		return this.claims(claims);
	}

	public OidcTokenBuilder otherClaims(Map<String, Object> claims) {
		return this.claims(claims);
	}

	public OidcTokenBuilder updatedAt(Instant value) {
		return setIfNonEmpty("", value);
	}

	protected OidcTokenBuilder setIfNonEmpty(String claimName, String claimValue) {
		if (StringUtils.hasText(claimValue)) {
			this.put(claimName, claimValue);
		} else {
			this.remove(claimName);
		}
		return this;
	}

	protected OidcTokenBuilder setIfNonEmpty(String claimName, Collection<String> claimValue) {
		if (claimValue == null || claimValue.size() == 0) {
			this.remove(claimName);
		} else if (claimValue.size() == 0) {
			this.setIfNonEmpty(claimName, claimValue.iterator().next());
		} else {
			this.put(claimName, claimValue);
		}
		return this;
	}

	protected OidcTokenBuilder setIfNonEmpty(String claimName, Instant claimValue) {
		if (claimValue == null) {
			this.remove(claimName);
		} else {
			this.put(claimName, claimValue.getEpochSecond());
		}
		return this;
	}

	protected OidcTokenBuilder setIfNonEmpty(String claimName, Boolean claimValue) {
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
