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
package com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak;

import java.time.Instant;

import org.keycloak.representations.AddressClaimSet;
import org.keycloak.representations.IDToken;
import org.springframework.util.StringUtils;

import com.c4_soft.springaddons.security.oauth2.test.annotations.ClaimSet;
import com.c4_soft.springaddons.security.oauth2.test.annotations.IdTokenClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OidcStandardClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithAddress;

class IDTokenBuilderHelper {

	public static IDToken feed(
			IDToken token,
			IdTokenClaims idTokenAnnotation,
			OidcStandardClaims oidcIdAnnotation,
			ClaimSet privateClaims) {
		if (!StringUtils.isEmpty(idTokenAnnotation.iss())) {
			token.issuer(idTokenAnnotation.iss());
		}
		if (StringUtils.hasLength(idTokenAnnotation.exp())) {
			token.exp(Instant.parse(idTokenAnnotation.exp()).getEpochSecond());
		}
		if (StringUtils.hasLength(idTokenAnnotation.iat())) {
			token.iat(Instant.parse(idTokenAnnotation.iat()).getEpochSecond());
		}
		if (StringUtils.hasLength(idTokenAnnotation.authTime())) {
			token.setAuth_time(Instant.parse(idTokenAnnotation.authTime()).getEpochSecond());
		}
		token.subject(idTokenAnnotation.sub());
		token.audience(idTokenAnnotation.aud());
		token.setNonce(idTokenAnnotation.nonce());
		token.setAcr(idTokenAnnotation.acr());
		token.issuedFor(idTokenAnnotation.azp());

		if (StringUtils.hasLength(oidcIdAnnotation.updatedAt())) {
			token.setUpdatedAt(Instant.parse(oidcIdAnnotation.updatedAt()).getEpochSecond());
		}
		token.setAddress(build(oidcIdAnnotation.address()));
		token.setBirthdate(nullIfEmpty(oidcIdAnnotation.birthdate()));
		token.setEmail(nullIfEmpty(oidcIdAnnotation.email()));
		token.setEmailVerified(oidcIdAnnotation.emailVerified());
		token.setFamilyName(nullIfEmpty(oidcIdAnnotation.familyName()));
		token.setGender(nullIfEmpty(oidcIdAnnotation.gender()));
		token.setGivenName(nullIfEmpty(oidcIdAnnotation.givenName()));
		token.setLocale(nullIfEmpty(oidcIdAnnotation.locale()));
		token.setMiddleName(nullIfEmpty(oidcIdAnnotation.middleName()));
		token.setName(nullIfEmpty(oidcIdAnnotation.name()));
		token.setNickName(nullIfEmpty(oidcIdAnnotation.nickName()));
		token.setPhoneNumber(nullIfEmpty(oidcIdAnnotation.phoneNumber()));
		token.setPhoneNumberVerified(oidcIdAnnotation.phoneNumberVerified());
		token.setPreferredUsername(nullIfEmpty(oidcIdAnnotation.preferredUsername()));
		token.setPicture(nullIfEmpty(oidcIdAnnotation.picture()));
		token.setProfile(nullIfEmpty(oidcIdAnnotation.profile()));
		token.setWebsite(nullIfEmpty(oidcIdAnnotation.website()));

		for (var claim : privateClaims.intClaims()) {
			token.setOtherClaims(claim.name(), claim.value());
		}
		for (var claim : privateClaims.longClaims()) {
			token.setOtherClaims(claim.name(), claim.value());
		}
		for (var claim : privateClaims.stringClaims()) {
			token.setOtherClaims(claim.name(), claim.value());
		}
		for (var claim : privateClaims.stringArrayClaims()) {
			token.setOtherClaims(claim.name(), claim.value());
		}

		return token;
	}

	private static AddressClaimSet build(WithAddress addressAnnotation) {
		final var claims = new AddressClaimSet();
		claims.setCountry(nullIfEmpty(addressAnnotation.country()));
		claims.setFormattedAddress(nullIfEmpty(addressAnnotation.formattedAddress()));
		claims.setLocality(nullIfEmpty(addressAnnotation.locality()));
		claims.setPostalCode(nullIfEmpty(addressAnnotation.postalCode()));
		claims.setRegion(nullIfEmpty(addressAnnotation.region()));
		claims.setStreetAddress(nullIfEmpty(addressAnnotation.streetAddress()));
		return claims;
	}

	private static String nullIfEmpty(String str) {
		return StringUtils.isEmpty(str) ? null : str;
	}

}
