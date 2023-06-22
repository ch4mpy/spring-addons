/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */

package com.c4_soft.springaddons.security.oauth2.test.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;

import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.util.StringUtils;

import com.c4_soft.springaddons.security.oauth2.test.Defaults;
import com.c4_soft.springaddons.security.oauth2.test.OpenidClaimSetBuilder;

/**
 * Configures claims defined at
 * <a href= "https://datatracker.ietf.org/doc/html/rfc7519#section-4.1">https://datatracker.ietf.org/doc/html/rfc7519#section-4.1</a> and
 * <a target="_blank" href= "https://openid.net/specs/openid-connect-core-1_0.html#IDToken">https://openid.net/specs/openid-connect-core-1_0.html#IDToken</a>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface OpenIdClaims {

	String acr() default "";

	String[] amr() default {};

	String[] aud() default {};

	String azp() default "";

	/**
	 * @return authentication instant formated as {@link DateTimeFormatter#ISO_INSTANT}
	 */
	String authTime() default "";

	/**
	 * @return expiration instant formated as {@link DateTimeFormatter#ISO_INSTANT}
	 */
	String exp() default "";

	/**
	 * @return issue instant formated as {@link DateTimeFormatter#ISO_INSTANT}
	 */
	String iat() default "";

	/**
	 * @return jti (JWT unique identifier)
	 */
	String jti() default "";

	/**
	 * @return nbf (not before) instant formated as {@link DateTimeFormatter#ISO_INSTANT}
	 */
	String nbf() default "";

	/**
	 * @return to be parsed as URL
	 */
	String iss() default "";

	String nonce() default "";

	String sub() default Defaults.SUBJECT;

	String sessionState() default "";

	String accessTokenHash() default "";

	String authorizationCodeHash() default "";

	OpenIdAddress address() default @OpenIdAddress();

	/**
	 * @return End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DDformat
	 */
	String birthdate() default "";

	String email() default "";

	boolean emailVerified() default false;

	String familyName() default "";

	String gender() default "";

	String givenName() default "";

	String locale() default "";

	String middleName() default "";

	String name() default "";

	String nickName() default "";

	String phoneNumber() default "";

	boolean phoneNumberVerified() default false;

	String picture() default "";

	String preferredUsername() default Defaults.AUTH_NAME;

	String profile() default "";

	/**
	 * @return issue instant formated as {@link DateTimeFormatter#ISO_INSTANT}
	 */
	String updatedAt() default "";

	String website() default "";

	String zoneinfo() default "";

	/**
	 * @return intended to define private claims but any claim can be defined there. In case of conflict with an OpenID standard claim, the standard claim wins.
	 */
	Claims otherClaims() default @Claims();

	String usernameClaim() default StandardClaimNames.SUB;

	/**
	 * @return claims from a JSON file on the classpath. In case of conflict this claims have the lowest precedence: jsonFile < otherClaims < OpenID standard
	 *         claims
	 */
	ClasspathClaims jsonFile() default @ClasspathClaims();

	public static class Builder {

		private Builder() {
		}

		public static OpenidClaimSetBuilder of(OpenIdClaims tokenAnnotation) {
			final var token = new OpenidClaimSetBuilder();

			token.putAll(ClasspathClaims.Support.parse(tokenAnnotation.jsonFile()));
			token.putAll(Claims.Token.of(tokenAnnotation.otherClaims()));

			token.name(tokenAnnotation.usernameClaim());
			if (StringUtils.hasText(tokenAnnotation.iss())) {
				try {
					token.issuer(new URL(tokenAnnotation.iss()));
				} catch (final MalformedURLException e) {
					throw new InvalidClaimException(e);
				}
			}
			if (StringUtils.hasLength(tokenAnnotation.exp())) {
				token.expiresAt(Instant.parse(tokenAnnotation.exp()));
			}
			if (StringUtils.hasLength(tokenAnnotation.iat())) {
				token.issuedAt(Instant.parse(tokenAnnotation.iat()));
			}
			if (StringUtils.hasLength(tokenAnnotation.authTime())) {
				token.authTime(Instant.parse(tokenAnnotation.authTime()));
			}
			if (StringUtils.hasLength(tokenAnnotation.sessionState())) {
				token.sessionState(tokenAnnotation.sessionState());
			}
			if (StringUtils.hasLength(tokenAnnotation.sessionState())) {
				token.accessTokenHash(tokenAnnotation.accessTokenHash());
			}
			if (StringUtils.hasLength(tokenAnnotation.sessionState())) {
				token.authorizationCodeHash(tokenAnnotation.authorizationCodeHash());
			}
			token.subject(tokenAnnotation.sub()).audience(Arrays.asList(tokenAnnotation.aud())).nonce(tokenAnnotation.nonce()).acr(tokenAnnotation.acr())
					.amr(Arrays.asList(tokenAnnotation.amr())).azp(tokenAnnotation.azp());

			if (StringUtils.hasLength(tokenAnnotation.updatedAt())) {
				token.updatedAt(Instant.parse(tokenAnnotation.updatedAt()));
			}
			return token.address(OpenIdAddress.Claim.of(tokenAnnotation.address())).birthdate(nullIfEmpty(tokenAnnotation.birthdate()))
					.email(nullIfEmpty(tokenAnnotation.email())).emailVerified(tokenAnnotation.emailVerified())
					.familyName(nullIfEmpty(tokenAnnotation.familyName())).gender(nullIfEmpty(tokenAnnotation.gender()))
					.givenName(nullIfEmpty(tokenAnnotation.givenName())).jwtId(tokenAnnotation.jti()).locale(nullIfEmpty(tokenAnnotation.locale()))
					.middleName(nullIfEmpty(tokenAnnotation.middleName())).name(nullIfEmpty(tokenAnnotation.name()))
					.nickname(nullIfEmpty(tokenAnnotation.nickName())).phoneNumber(nullIfEmpty(tokenAnnotation.phoneNumber()))
					.phoneNumberVerified(tokenAnnotation.phoneNumberVerified()).preferredUsername(nullIfEmpty(tokenAnnotation.preferredUsername()))
					.picture(nullIfEmpty(tokenAnnotation.picture())).profile(nullIfEmpty(tokenAnnotation.profile()))
					.website(nullIfEmpty(tokenAnnotation.website()));
		}

		private static String nullIfEmpty(String str) {
			return StringUtils.hasText(str) ? str : null;
		}
	}
}
