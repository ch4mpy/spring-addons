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
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.support.AnnotationConsumer;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenId;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;

/**
 * <p>
 * Define the different {@link OAuthentication OAuthentication&lt;OpenidClaimSet&gt;} instances to run each of JUnit 5 &#64;ParameterizedTest with.
 * </p>
 * Usage:
 *
 * <pre>
 * &#64;OpenIdAuthenticationSource({ &#64;OpenId("NICE"), &#64;OpenId("VERY_NICE") })
 * void test(&#64;ParameterizedOpenId OAuthentication&lt;OpenidClaimSet&gt; auth) throws Exception {
 *     ...
 * }
 * </pre>
 *
 * @author     Jerome Wacongne ch4mp&#64;c4-soft.com
 * @deprecated use a {@link MethodSource &#64;MethodSource} in association with {@link ParameterizedAuthentication &#64;ParameterizedAuthentication} and
 *             {@link WithJwt.AuthenticationFactory}
 */
@Target({ ElementType.ANNOTATION_TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
@ArgumentsSource(OpenIdAuthenticationSource.AuthenticationProvider.class)
public @interface OpenIdAuthenticationSource {
	OpenId[] value() default {};

	static class AuthenticationProvider implements ArgumentsProvider, AnnotationConsumer<OpenIdAuthenticationSource> {
		private final OpenId.AuthenticationFactory authFactory = new OpenId.AuthenticationFactory();

		private Collection<OAuthentication<OpenidClaimSet>> arguments;

		@Override
		public void accept(OpenIdAuthenticationSource source) {
			arguments = Stream.of(source.value()).map(authFactory::authentication).toList();
		}

		@Override
		public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
			return arguments.stream().map(Arguments::of);
		}

	}
}
