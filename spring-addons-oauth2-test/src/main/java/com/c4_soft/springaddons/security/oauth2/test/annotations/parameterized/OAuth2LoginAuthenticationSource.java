package com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Collection;
import java.util.stream.Stream;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.support.AnnotationConsumer;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOAuth2Login;

/**
 * <p>
 * Define the different {@link OAuth2AuthenticationToken} instances to run each of JUnit 5 &#64;ParameterizedTest with.
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
 * @see    ParameterizedOAuth2Login
 */
@Target({ ElementType.ANNOTATION_TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
@ArgumentsSource(OAuth2LoginAuthenticationSource.AuthenticationProvider.class)
public @interface OAuth2LoginAuthenticationSource {
	WithOAuth2Login[] value() default {};

	static class AuthenticationProvider implements ArgumentsProvider, AnnotationConsumer<OAuth2LoginAuthenticationSource> {
		private final WithOAuth2Login.OAuth2AuthenticationTokenFactory authFactory = new WithOAuth2Login.OAuth2AuthenticationTokenFactory();

		private Collection<OAuth2AuthenticationToken> arguments;

		@Override
		public void accept(OAuth2LoginAuthenticationSource source) {
			arguments = Stream.of(source.value()).map(authFactory::authentication).toList();
		}

		@Override
		public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
			return arguments.stream().map(Arguments::of);
		}

	}
}
