/*
 * Copyright 2019 Jérôme Wacongne.
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

import static org.mockito.Mockito.mock;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.mockito.Mock;
import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.test.context.TestContext;

import com.c4_soft.springaddons.security.oauth2.test.MockAuthenticationBuilder;

/**
 * <p>
 * Populates {@link SecurityContext} with an {@link Authentication} {@link Mock}.
 * </p>
 * Sample usage:
 *
 * <pre>
 * &#64;Test
 * &#64;WithMockAuthentication
 * public demoDefaultUserNameAndAuthorities {
 *   // test as "user" granted with "ROLE_USER"
 * }
 *
 * &#64;Test
 * &#64;WithMockAuthentication(name = "Ch4mpy", authorities = { "ROLE_TESTER", "ROLE_AUTHOR" })
 * public demoCustomUserNameAndAuthorities {
 *   // test as "Ch4mpy" granted with "ROLE_TESTER", "ROLE_AUTHOR"
 * }
 *
 * &#64;Test
 * &#64;WithMockAuthentication(JwtAuthenticationToken.class)
 * public demoCustomAuthenticationImpl {
 *   final var jwt = mock(Jwt.class);
 *   when(jwt.getSubject()).thenReturn(auth.getName());
 *
 *   final var auth = (JwtAuthenticationToken) SecurityContextHolder.getContext();
 *   when(auth.getPrincipal()).thenReturn(jwt);
 *
 *   // test as "user" granted with "ROLE_USER", the Authentication in the SecurityContext being a JwtAuthenticationToken mock
 * }
 * </pre>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMockAuthentication.Factory.class)
public @interface WithMockAuthentication {

	@AliasFor("authType")
	Class<? extends Authentication> value() default Authentication.class;

	@AliasFor("value")
	Class<? extends Authentication> authType() default Authentication.class;

	Class<?> principalType() default String.class;

	String name() default "user";

	String[] authorities() default { "ROLE_USER" };

	/**
	 * Determines when the {@link SecurityContext} is setup. The default is before {@link TestExecutionEvent#TEST_METHOD} which occurs during
	 * {@link org.springframework.test.context.TestExecutionListener#beforeTestMethod(TestContext)}
	 *
	 * @return the {@link TestExecutionEvent} to initialize before
	 */
	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	public static final class Factory implements WithSecurityContextFactory<WithMockAuthentication> {
		@Override
		public SecurityContext createSecurityContext(WithMockAuthentication annotation) {
			final SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(authentication(annotation));

			return context;
		}

		public Authentication authentication(WithMockAuthentication annotation) {
			return new MockAuthenticationBuilder<>(annotation.authType(), mock(annotation.principalType())).name(annotation.name())
					.authorities(annotation.authorities()).build();
		}
	}
}
