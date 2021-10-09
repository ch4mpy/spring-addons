/*
 * Copyright 2020 Jérôme Wacongne.
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
package com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak;

import java.time.Instant;

import org.keycloak.representations.AddressClaimSet;
import org.keycloak.representations.IDToken;
import org.springframework.util.StringUtils;

import com.c4_soft.springaddons.security.oauth2.test.annotations.IntClaim;
import com.c4_soft.springaddons.security.oauth2.test.annotations.JsonArrayClaim;
import com.c4_soft.springaddons.security.oauth2.test.annotations.JsonObjectClaim;
import com.c4_soft.springaddons.security.oauth2.test.annotations.LongClaim;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdAddress;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.StringArrayClaim;
import com.c4_soft.springaddons.security.oauth2.test.annotations.StringClaim;

class IDTokenBuilderHelper {

	public static IDToken feed(IDToken token, OpenIdClaims claimsAnnotation) {
		token.setAcr(claimsAnnotation.acr());
		token.audience(claimsAnnotation.aud());
		if (StringUtils.hasLength(claimsAnnotation.authTime())) {
			token.setAuth_time(Instant.parse(claimsAnnotation.authTime()).getEpochSecond());
		}
		token.issuedFor(claimsAnnotation.azp());
		if (StringUtils.hasLength(claimsAnnotation.exp())) {
			token.exp(Instant.parse(claimsAnnotation.exp()).getEpochSecond());
		}
		if (StringUtils.hasLength(claimsAnnotation.iat())) {
			token.iat(Instant.parse(claimsAnnotation.iat()).getEpochSecond());
		}
		if (StringUtils.hasText(claimsAnnotation.iss())) {
			token.issuer(claimsAnnotation.iss());
		}
		if (StringUtils.hasText(claimsAnnotation.jti())) {
			token.id(claimsAnnotation.jti());
		}
		if (StringUtils.hasText(claimsAnnotation.nbf())) {
			token.nbf(Instant.parse(claimsAnnotation.nbf()).getEpochSecond());
		}
		token.setNonce(claimsAnnotation.nonce());
		token.setSessionState(nullIfEmpty(claimsAnnotation.sessionState()));
		token.subject(claimsAnnotation.sub());

		if (StringUtils.hasLength(claimsAnnotation.updatedAt())) {
			token.setUpdatedAt(Instant.parse(claimsAnnotation.updatedAt()).getEpochSecond());
		}
		token.setAddress(build(claimsAnnotation.address()));
		token.setBirthdate(nullIfEmpty(claimsAnnotation.birthdate()));
		token.setEmail(nullIfEmpty(claimsAnnotation.email()));
		token.setEmailVerified(claimsAnnotation.emailVerified());
		token.setFamilyName(nullIfEmpty(claimsAnnotation.familyName()));
		token.setGender(nullIfEmpty(claimsAnnotation.gender()));
		token.setGivenName(nullIfEmpty(claimsAnnotation.givenName()));
		token.setLocale(nullIfEmpty(claimsAnnotation.locale()));
		token.setMiddleName(nullIfEmpty(claimsAnnotation.middleName()));
		token.setName(nullIfEmpty(claimsAnnotation.name()));
		token.setNickName(nullIfEmpty(claimsAnnotation.nickName()));
		token.setPhoneNumber(nullIfEmpty(claimsAnnotation.phoneNumber()));
		token.setPhoneNumberVerified(claimsAnnotation.phoneNumberVerified());
		token.setPreferredUsername(nullIfEmpty(claimsAnnotation.preferredUsername()));
		token.setPicture(nullIfEmpty(claimsAnnotation.picture()));
		token.setProfile(nullIfEmpty(claimsAnnotation.profile()));
		token.setWebsite(nullIfEmpty(claimsAnnotation.website()));

		for (final IntClaim claim : claimsAnnotation.otherClaims().intClaims()) {
			token.setOtherClaims(claim.name(), claim.value());
		}
		for (final LongClaim claim : claimsAnnotation.otherClaims().longClaims()) {
			token.setOtherClaims(claim.name(), claim.value());
		}
		for (final StringClaim claim : claimsAnnotation.otherClaims().stringClaims()) {
			token.setOtherClaims(claim.name(), claim.value());
		}
		for (final StringArrayClaim claim : claimsAnnotation.otherClaims().stringArrayClaims()) {
			token.setOtherClaims(claim.name(), claim.value());
		}
		for (final JsonObjectClaim claim : claimsAnnotation.otherClaims().jsonObjectClaims()) {
			token.setOtherClaims(claim.name(), JsonObjectClaim.Support.parse(claim));
		}
		for (final JsonArrayClaim claim : claimsAnnotation.otherClaims().jsonArrayClaims()) {
			token.setOtherClaims(claim.name(), JsonArrayClaim.Support.parse(claim));
		}

		return token;
	}

	private static AddressClaimSet build(OpenIdAddress addressAnnotation) {
		final AddressClaimSet claims = new AddressClaimSet();
		claims.setCountry(nullIfEmpty(addressAnnotation.country()));
		claims.setFormattedAddress(nullIfEmpty(addressAnnotation.formattedAddress()));
		claims.setLocality(nullIfEmpty(addressAnnotation.locality()));
		claims.setPostalCode(nullIfEmpty(addressAnnotation.postalCode()));
		claims.setRegion(nullIfEmpty(addressAnnotation.region()));
		claims.setStreetAddress(nullIfEmpty(addressAnnotation.streetAddress()));
		return claims;
	}

	private static String nullIfEmpty(String str) {
		return StringUtils.hasText(str) ? str : null;
	}

}
