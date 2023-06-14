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
 * Shortcut for {@link ConvertWith &#64;ConvertWith(ParameterizedOidcLogin.AuthenticationArgumentProcessor.class)}, which populates the passed
 * &#64;ParameterizedTest parameter.
 * </p>
 * Usage:
 *
 * <pre>
 * &#64;OidcLoginAuthenticationSource({ &#64;WithOidcLogin("NICE"), &#64;WithOidcLogin("VERY_NICE") })
 * void test(&#64;ParameterizedOidcLogin OAuth2AuthenticationToken auth) throws Exception {
 *     ...
 * }
 * </pre>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see    OidcLoginAuthenticationSource
 * @since  6.1.12
 */
@Target({ ElementType.ANNOTATION_TYPE, ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
@ConvertWith(ParameterizedOidcLogin.AuthenticationArgumentProcessor.class)
public @interface ParameterizedOidcLogin {

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