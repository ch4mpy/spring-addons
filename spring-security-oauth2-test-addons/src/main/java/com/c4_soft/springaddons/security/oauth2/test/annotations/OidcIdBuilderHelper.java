/*
 * Copyright 2020 Jérôme Wacongne.
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
package com.c4_soft.springaddons.security.oauth2.test.annotations;

import java.time.Instant;

import org.springframework.util.StringUtils;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdBuilder;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdBuilder.AddressClaim;

class OidcIdBuilderHelper {

	static OidcIdBuilder feed(OidcIdBuilder token, OidcStandardClaims tokenAnnotation) {
		if (StringUtils.hasLength(tokenAnnotation.updatedAt())) {
			token.updatedAt(Instant.parse(tokenAnnotation.updatedAt()));
		}
		return token.address(build(tokenAnnotation.address()))
				.birthdate(nullIfEmpty(tokenAnnotation.birthdate()))
				.email(nullIfEmpty(tokenAnnotation.email()))
				.emailVerified(tokenAnnotation.emailVerified())
				.familyName(nullIfEmpty(tokenAnnotation.familyName()))
				.gender(nullIfEmpty(tokenAnnotation.gender()))
				.givenName(nullIfEmpty(tokenAnnotation.givenName()))
				.locale(nullIfEmpty(tokenAnnotation.locale()))
				.middleName(nullIfEmpty(tokenAnnotation.middleName()))
				.name(nullIfEmpty(tokenAnnotation.name()))
				.nickname(nullIfEmpty(tokenAnnotation.nickName()))
				.phoneNumber(nullIfEmpty(tokenAnnotation.phoneNumber()))
				.phoneNumberVerified(tokenAnnotation.phoneNumberVerified())
				.preferredUsername(nullIfEmpty(tokenAnnotation.preferredUsername()))
				.picture(nullIfEmpty(tokenAnnotation.picture()))
				.profile(nullIfEmpty(tokenAnnotation.profile()))
				.website(nullIfEmpty(tokenAnnotation.website()));
	}

	private static AddressClaim build(WithAddress addressAnnotation) {
		return new AddressClaim().country(nullIfEmpty(addressAnnotation.country()))
				.formatted(nullIfEmpty(addressAnnotation.formattedAddress()))
				.locality(nullIfEmpty(addressAnnotation.locality()))
				.postalCode(nullIfEmpty(addressAnnotation.postalCode()))
				.region(nullIfEmpty(addressAnnotation.region()))
				.streetAddress(nullIfEmpty(addressAnnotation.streetAddress()));
	}

	private static String nullIfEmpty(String str) {
		return StringUtils.hasText(str) ? str : null;
	}

}
