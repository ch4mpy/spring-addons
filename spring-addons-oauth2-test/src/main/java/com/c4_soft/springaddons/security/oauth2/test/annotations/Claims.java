/*
 * Copyright 2019 Jérôme Wacongne
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

package com.c4_soft.springaddons.security.oauth2.test.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.c4_soft.springaddons.security.oauth2.ModifiableClaimSet;

@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface Claims {

	IntClaim[] intClaims() default {};

	LongClaim[] longClaims() default {};

	StringClaim[] stringClaims() default {};

	StringArrayClaim[] stringArrayClaims() default {};

	JsonObjectClaim[] jsonObjectClaims() default {};

	JsonArrayClaim[] jsonArrayClaims() default {};

	public static class Token {
		private Token() {
		}

		public static ModifiableClaimSet of(Claims annotation) {
			final var claims = new ModifiableClaimSet();
			for (final IntClaim claim : annotation.intClaims()) {
				claims.claim(claim.name(), claim.value());
			}
			for (final LongClaim claim : annotation.longClaims()) {
				claims.claim(claim.name(), claim.value());
			}
			for (final StringClaim claim : annotation.stringClaims()) {
				claims.claim(claim.name(), claim.value());
			}
			for (final StringArrayClaim claim : annotation.stringArrayClaims()) {
				claims.claim(claim.name(), claim.value());
			}
			for (final JsonObjectClaim claim : annotation.jsonObjectClaims()) {
				claims.claim(claim.name(), JsonObjectClaim.Support.parse(claim));
			}
			for (final JsonArrayClaim claim : annotation.jsonArrayClaims()) {
				claims.claim(claim.name(), JsonArrayClaim.Support.parse(claim));
			}
			return claims;
		}

	}

}
