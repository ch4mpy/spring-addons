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
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;

/**
 * <p>
 * Define the different {@link JwtAuthenticationToken} instances to run each of JUnit 5 &#64;ParameterizedTest with.
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
 * @see    ParameterizedJwtAuth
 */
@Target({ ElementType.ANNOTATION_TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
@ArgumentsSource(JwtAuthenticationSource.AuthenticationProvider.class)
public @interface JwtAuthenticationSource {
	WithMockJwtAuth[] value() default {};

	static class AuthenticationProvider implements ArgumentsProvider, AnnotationConsumer<JwtAuthenticationSource> {
		private final WithMockJwtAuth.JwtAuthenticationTokenFactory authFactory = new WithMockJwtAuth.JwtAuthenticationTokenFactory();

		private Collection<JwtAuthenticationToken> arguments;

		@Override
		public void accept(JwtAuthenticationSource source) {
			arguments = Stream.of(source.value()).map(authFactory::authentication).toList();
		}

		@Override
		public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
			return arguments.stream().map(Arguments::of);
		}

	}
}
