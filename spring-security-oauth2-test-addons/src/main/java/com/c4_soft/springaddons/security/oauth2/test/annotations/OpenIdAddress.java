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

import org.springframework.util.StringUtils;

import com.c4_soft.springaddons.security.oauth2.test.OidcTokenBuilder.AddressClaim;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface OpenIdAddress {

	String formattedAddress() default "";

	String streetAddress() default "";

	String locality() default "";

	String region() default "";

	String postalCode() default "";

	String country() default "";

	public static class Claim {
		private Claim() {
		}

		public static AddressClaim of(OpenIdAddress addressAnnotation) {
			return new AddressClaim()
					.country(nullIfEmpty(addressAnnotation.country()))
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
}
