package com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.converter.TypedArgumentConverter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

/**
 * <p>
 * Shortcut for {@link ConvertWith &#64;ConvertWith(ParameterizedOAuth2Login.AuthenticationArgumentProcessor.class)}, which populates the passed
 * &#64;ParameterizedTest parameter.
 * </p>
 * Usage:
 *
 * <pre>
 * &#64;OAuth2LoginAuthenticationSource({ &#64;WithOAuth2Login("NICE"), &#64;WithOAuth2Login("VERY_NICE") })
 * void test(&#64;ParameterizedOAuth2Login OAuth2AuthenticationToken auth) throws Exception {
 *     ...
 * }
 * </pre>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see    OAuth2LoginAuthenticationSource
 * @since  6.1.12
 */
@Target({ ElementType.ANNOTATION_TYPE, ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
@ConvertWith(ParameterizedOAuth2Login.AuthenticationArgumentProcessor.class)
public @interface ParameterizedOAuth2Login {

	static class AuthenticationArgumentProcessor extends TypedArgumentConverter<OAuth2AuthenticationToken, OAuth2AuthenticationToken> {

		protected AuthenticationArgumentProcessor() {
			super(OAuth2AuthenticationToken.class, OAuth2AuthenticationToken.class);
		}

		@Override
		protected OAuth2AuthenticationToken convert(OAuth2AuthenticationToken source) {
			SecurityContextHolder.getContext().setAuthentication(source);

			return source;
		}

	}
}