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
import java.time.format.DateTimeFormatter;

/**
 * Configures claims defined at: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface WithIDToken {
	/**
	 * @return to be parsed as URL
	 */
	String iss() default "";

	String sub() default "";

	String[] aud() default {};

	/**
	 * @return expiration instant formated as {@link DateTimeFormatter#ISO_INSTANT}
	 */
	String exp() default "";

	/**
	 * @return issue instant formated as {@link DateTimeFormatter#ISO_INSTANT}
	 */
	String iat() default "";

	/**
	 * @return authentication instant formated as {@link DateTimeFormatter#ISO_INSTANT}
	 */
	String authTime() default "";

	String nonce() default "";

	String acr() default "";

	String amr() default "";

	String azp() default "";
}
