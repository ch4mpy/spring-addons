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
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockBearerTokenAuthentication;

/**
 * <p>
 * Define the different {@link BearerTokenAuthentication} instances to run each of JUnit 5 &#64;ParameterizedTest with.
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
 * @see    ParameterizedBearerAuth
 */
@Target({ ElementType.ANNOTATION_TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
@ArgumentsSource(BearerAuthenticationSource.AuthenticationProvider.class)
public @interface BearerAuthenticationSource {
	WithMockBearerTokenAuthentication[] value() default {};

	static class AuthenticationProvider implements ArgumentsProvider, AnnotationConsumer<BearerAuthenticationSource> {
		private final WithMockBearerTokenAuthentication.AuthenticationFactory authFactory = new WithMockBearerTokenAuthentication.AuthenticationFactory();

		private Collection<BearerTokenAuthentication> arguments;

		@Override
		public void accept(BearerAuthenticationSource source) {
			arguments = Stream.of(source.value()).map(authFactory::authentication).toList();
		}

		@Override
		public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
			return arguments.stream().map(Arguments::of);
		}

	}
}
