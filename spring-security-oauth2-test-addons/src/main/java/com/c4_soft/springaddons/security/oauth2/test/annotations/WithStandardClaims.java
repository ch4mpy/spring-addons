/*
 * Copyright 2019 Jérôme Wacongne
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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.c4_soft.springaddons.security.oauth2.test.annotations.keycloak.WithAddress;

/**
 * Configures claims defined at: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface WithStandardClaims {
	String sub() default "";

	String name() default "";

	String givenName() default "";

	String familyName() default "";

	String middleName() default "";

	String nickname() default "";

	String preferredUsername() default "";

	String profile() default "";

	String picture() default "";

	String website() default "";

	String email() default "";

	boolean emailVerified() default false;

	String gender() default "";

	String birthdate() default "";

	String zoneinfo() default "";

	String locale() default "";

	String phoneNumber() default "";

	boolean phoneNumberVerified() default false;

	WithAddress address() default @WithAddress();

	String updatedAt() default "";
}
