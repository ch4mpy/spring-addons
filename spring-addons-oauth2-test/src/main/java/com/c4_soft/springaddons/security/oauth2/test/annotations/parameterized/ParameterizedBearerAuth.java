package com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.converter.TypedArgumentConverter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;

/**
 * <p>
 * Shortcut for {@link ConvertWith &#64;ConvertWith(ParameterizedBearerAuth.AuthenticationArgumentProcessor.class)}, which populates the passed
 * &#64;ParameterizedTest parameter.
 * </p>
 * Usage:
 *
 * <pre>
 * &#64;BearerAuthenticationSource({ &#64;WithMockBearerTokenAuthentication("NICE"), &#64;WithMockBearerTokenAuthentication("VERY_NICE") })
 * void test(&#64;ParameterizedBearerAuth BearerTokenAuthentication auth) throws Exception {
 *     ...
 * }
 * </pre>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see    BearerAuthenticationSource
 */
@Target({ ElementType.ANNOTATION_TYPE, ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
@ConvertWith(ParameterizedBearerAuth.AuthenticationArgumentProcessor.class)
public @interface ParameterizedBearerAuth {

	static class AuthenticationArgumentProcessor extends TypedArgumentConverter<BearerTokenAuthentication, BearerTokenAuthentication> {

		protected AuthenticationArgumentProcessor() {
			super(BearerTokenAuthentication.class, BearerTokenAuthentication.class);
		}

		@Override
		protected BearerTokenAuthentication convert(BearerTokenAuthentication source) {
			SecurityContextHolder.getContext().setAuthentication(source);

			return source;
		}

	}
}