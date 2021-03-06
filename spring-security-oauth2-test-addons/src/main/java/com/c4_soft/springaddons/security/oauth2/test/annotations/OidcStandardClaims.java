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

import com.c4_soft.springaddons.security.oauth2.test.Defaults;

/**
 * Configures claims defined at <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims</a>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface OidcStandardClaims {

	WithAddress address() default @WithAddress();

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

	String updatedAt() default "";

	String website() default "";

	String zoneinfo() default "";
}
