/*
 * Copyright 2019 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.test.context.support;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.configuration.Defaults;
import org.springframework.security.test.context.support.WithMockAuthentication.Factory;
import org.springframework.security.test.support.SimpleTestingAuthenticationTokenBuilder;
import org.springframework.test.context.TestContext;

/**
 * <p>
 * A lot like {@link WithMockUser @WithMockUser}: when used with {@link WithSecurityContextTestExecutionListener} this
 * annotation can be added to a test method to emulate running with a {@link TestingAuthenticationToken}.
 * </p>
 * Built authentication characteristics
 * <ul>
 * <li>{@link Authentication#getPrincipal() getPrincipal()} returns a String (authentication name, {@code "user"} by default)</li>
 * <li>{@link Authentication#getAuthorities() authorities} will be a collection of {@link SimpleGrantedAuthority} as
 * defined by this annotation {@link #authorities()} ({@code "ROLE_USER" } by default)</li>
 * </ul>
 *
 * Sample Usage:
 *
 * <pre>
 * &#64;WithMockAuthentication
 * &#64;Test
 * public void testSomethingWithDefaultAuthentication() {
 *   //identified as "user" granted with [ROLE_USER]
 *   ...
 * }
 *
 * &#64;WithMockAuthentication({"ROLE_USER", "ROLE_ADMIN"})
 * &#64;Test
 * public void testSomethingWithCustomAuthorities() {
 *   //identified as "user" granted with [ROLE_USER, ROLE_ADMIN]
 *   ...
 * }
 *
 * &#64;WithMockAuthentication(name = "ch4mpy")
 * &#64;Test
 * public void testSomethingWithCustomName() {
 *   //identified as "ch4mpy" granted with [ROLE_USER]
 *   ...
 * }
 * </pre>
 *
 * @see TestingAuthenticationToken
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 *
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = Factory.class)
public @interface WithMockAuthentication {

	@AliasFor("authorities")
	String[] value() default { "ROLE_USER" };

	@AliasFor("value")
	String[] authorities() default { "ROLE_USER" };

	String name() default Defaults.AUTH_NAME;

	/**
	 * Determines when the {@link SecurityContext} is setup. The default is before
	 * {@link TestExecutionEvent#TEST_METHOD} which occurs during
	 * {@link org.springframework.test.context.TestExecutionListener#beforeTestMethod(TestContext)}
	 * @return the {@link TestExecutionEvent} to initialize before
	 */
	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	public final class Factory implements WithSecurityContextFactory<WithMockAuthentication> {
		@Override
		public SecurityContext createSecurityContext(WithMockAuthentication annotation) {
			final SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(simpleTestingAuthenticationToken(annotation));

			return context;
		}

		public TestingAuthenticationToken simpleTestingAuthenticationToken(WithMockAuthentication annotation) {
			return new SimpleTestingAuthenticationTokenBuilder()
					.name(annotation.name())
					.authorities(annotation.authorities())
					.build();
		}
	}
}
