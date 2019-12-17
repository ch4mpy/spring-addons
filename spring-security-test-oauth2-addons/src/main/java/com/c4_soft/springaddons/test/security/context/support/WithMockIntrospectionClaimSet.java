/*
 * Copyright 2019 Jérôme Wacongne.
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
package com.c4_soft.springaddons.test.security.context.support;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.AliasFor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.util.StringUtils;

import com.c4_soft.oauth2.rfc7662.IntrospectionClaimNames;
import com.c4_soft.oauth2.rfc7662.IntrospectionClaimSet;
import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.OAuth2ClaimSetAuthentication;
import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesIntrospectionClaimSet;
import com.c4_soft.springaddons.test.security.context.support.WithMockIntrospectionClaimSet.Factory;
import com.c4_soft.springaddons.test.security.support.Defaults;
import com.c4_soft.springaddons.test.security.support.introspection.IntrospectionClaimSetAuthenticationTestingBuilder;

/**
 * Annotation to setup test {@link SecurityContext} with an
 * {@link OAuth2ClaimSetAuthentication}&lt;{@link WithAuthoritiesIntrospectionClaimSet}&gt; (OAuth2 authentication with
 * token claim-set embedded authorities)
 *
 * Sample usage:
 *
 * <pre>
    &#64;Test
    &#64;WithMockIntrospectionClaimSet({"ROLE_USER", "ROLE_ADMIN"})
    public void test() {
       ...
    }
 * </pre>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = Factory.class)
public @interface WithMockIntrospectionClaimSet {

	@AliasFor("authorities")
	String[] value() default {};

	@AliasFor("value")
	String[] authorities() default {};

	@AliasFor("username")
	String name() default "";

	@AliasFor("name")
	String username() default "";

	String subject() default "";

	StringAttribute[] claims() default {};

	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	public final class Factory
			extends
			AbstractWithClaimSetFactory<WithMockIntrospectionClaimSet, IntrospectionClaimSet> {

		private final StringAttributeParserSupport parsingSupport = new StringAttributeParserSupport();

		@Autowired
		public Factory(Converter<Map<String, Object>, Set<GrantedAuthority>> authoritiesConverter) {
			super(
					authoritiesConverter,
					new IntrospectionClaimSetAuthenticationTestingBuilder<>(
							authoritiesConverter,
							claimsMap -> new IntrospectionClaimSet(claimsMap)));
		}

		@Override
		protected String[] authoritiesOverride(WithMockIntrospectionClaimSet annotation) {
			return annotation.authorities();
		}

		@Override
		protected Map<String, Object> claimsMap(WithMockIntrospectionClaimSet annotation) {
			final var claimsBuilder = IntrospectionClaimSet.builder();
			parsingSupport.parse(annotation.claims()).forEach(claimsBuilder::claim);

			if (StringUtils.hasLength(annotation.subject())) {
				claimsBuilder.subject(annotation.subject());
			}
			if (StringUtils.hasLength(annotation.username())) {
				claimsBuilder.username(annotation.username());
			}
			if (!claimsBuilder.containsKey(IntrospectionClaimNames.USERNAME.value)) {
				claimsBuilder.username(Defaults.AUTH_NAME);
			}

			return claimsBuilder;
		}
	}
}
