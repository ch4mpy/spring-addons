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

import java.time.Instant;
import java.util.Map;

import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.util.StringUtils;

import com.c4_soft.springaddons.security.oauth2.ModifiableClaimSet;

/**
 * https://openid.net/specs/openid-connect-core-1_0.html
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OidcIdBuilder extends IdTokenBuilder<OidcIdBuilder> {

	private static final long serialVersionUID = 8050195176203128543L;

	public OidcIdBuilder() {
		super();
	}

	public OidcIdBuilder(Map<String, Object> other) {
		super(other);
	}

	@Override
	public OidcId build() {
		return new OidcId(this);
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
