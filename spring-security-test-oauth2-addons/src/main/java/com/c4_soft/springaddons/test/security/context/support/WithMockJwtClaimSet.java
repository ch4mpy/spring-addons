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
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.AliasFor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.util.StringUtils;

import com.c4_soft.oauth2.rfc7519.JwtClaimSet;
import com.c4_soft.oauth2.rfc7519.JwtRegisteredClaimNames;
import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.OAuth2ClaimSetAuthentication;
import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesJwtClaimSet;
import com.c4_soft.springaddons.test.security.context.support.WithMockJwtClaimSet.Factory;
import com.c4_soft.springaddons.test.security.support.Defaults;
import com.c4_soft.springaddons.test.security.support.jwt.JwtClaimSetAuthenticationTestingBuilder;

/**
 * Annotation to setup test {@link SecurityContext} with an
 * {@link OAuth2ClaimSetAuthentication}&lt;{@link WithAuthoritiesJwtClaimSet}&gt; (OAuth2 authentication with token
 * claim-set embedded authorities)
 *
 * Sample usage:
 *
 * <pre>
 * &#64;Test
 * &#64;WithMockJwtClaimSet({"ROLE_USER", "ROLE_ADMIN"})
 * public void test() {
 *     ...
 * }
 * </pre>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = Factory.class)
public @interface WithMockJwtClaimSet {

	@AliasFor("authorities")
	String[] value() default {};

	@AliasFor("value")
	String[] authorities() default {};

	@AliasFor("subject")
	String name() default "";

	@AliasFor("name")
	String subject() default "";

	StringAttribute[] claims() default {};

	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	public final class Factory implements WithSecurityContextFactory<WithMockJwtClaimSet> {
		private final StringAttributeParserSupport parsingSupport = new StringAttributeParserSupport();

		private final Converter<Map<String, Object>, Set<GrantedAuthority>> authoritiesConverter;

		@Autowired
		public Factory(Converter<Map<String, Object>, Set<GrantedAuthority>> authoritiesConverter) {
			this.authoritiesConverter = authoritiesConverter;
		}

		@Override
		public SecurityContext createSecurityContext(WithMockJwtClaimSet annotation) {
			final SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(authentication(annotation));

			return context;
		}

		public OAuth2ClaimSetAuthentication<? extends JwtClaimSet> authentication(WithMockJwtClaimSet annotation) {
			final var claimsMap = new HashMap<String, Object>();
			parsingSupport.parse(annotation.claims()).forEach(claimsMap::put);

			if (StringUtils.hasLength(annotation.subject())) {
				claimsMap.put(JwtRegisteredClaimNames.SUBJECT.value, annotation.subject());
			} else if (!claimsMap.containsKey(JwtRegisteredClaimNames.SUBJECT.value)) {
				claimsMap.put(JwtRegisteredClaimNames.SUBJECT.value, Defaults.AUTH_NAME);
			}

			final var authBuilder = new JwtClaimSetAuthenticationTestingBuilder<>(
					authoritiesConverter,
					claims -> new JwtClaimSet(claims));
			authBuilder.claims(claims -> claims.putAll(claimsMap));

			if (annotation.authorities().length > 0) {
				authBuilder.authorities(annotation.authorities());
			} else if (authoritiesConverter.getClass().getName().contains("Mockito")) {
				authBuilder.authorities(Defaults.AUTHORITIES);
			}

			return authBuilder.build();
		}
	}
}
