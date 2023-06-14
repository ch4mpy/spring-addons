package com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.converter.TypedArgumentConverter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * <p>
 * Shortcut for {@link ConvertWith &#64;ConvertWith(ParameterizedJwtAuth.AuthenticationArgumentProcessor.class)}, which populates the passed
 * &#64;ParameterizedTest parameter.
 * </p>
 * Usage:
 *
 * <pre>
 * &#64;JwtAuthenticationSource({ &#64;WithMockJwtAuth("NICE"), &#64;WithMockJwtAuth("VERY_NICE") })
 * void test(&#64;ParameterizedJwtAuth JwtAuthenticationToken auth) throws Exception {
 *     ...
 * }
 * </pre>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see    JwtAuthenticationSource
 */
@Target({ ElementType.ANNOTATION_TYPE, ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
@ConvertWith(ParameterizedJwtAuth.AuthenticationArgumentProcessor.class)
public @interface ParameterizedJwtAuth {

	static class AuthenticationArgumentProcessor extends TypedArgumentConverter<JwtAuthenticationToken, JwtAuthenticationToken> {

		protected AuthenticationArgumentProcessor() {
			super(JwtAuthenticationToken.class, JwtAuthenticationToken.class);
		}

		@Override
		protected JwtAuthenticationToken convert(JwtAuthenticationToken source) {
			SecurityContextHolder.getContext().setAuthentication(source);

			return source;
		}

	}
}