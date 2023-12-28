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
import org.springframework.security.core.Authentication;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockAuthentication;

/**
 * <p>
 * Define the different {@link Authentication} instances to run each of JUnit 5 &#64;ParameterizedTest with.
 * </p>
 * Usage:
 *
 * <pre>
 * &#64;AuthenticationSource({ &#64;WithMockAuthentication("NICE"), &#64;WithMockAuthentication("VERY_NICE") })
 * void test(&#64;ParameterizedAuthentication Authentication auth) throws Exception {
 *     ...
 * }
 * </pre>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @since 6.1.12
 */
@Target({ ElementType.ANNOTATION_TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
@ArgumentsSource(AuthenticationSource.AuthenticationProvider.class)
public @interface AuthenticationSource {
    WithMockAuthentication[] value() default {};

    static class AuthenticationProvider implements ArgumentsProvider, AnnotationConsumer<AuthenticationSource> {
        private final WithMockAuthentication.Factory authFactory = new WithMockAuthentication.Factory();

        private Collection<Authentication> arguments;

        @Override
        public void accept(AuthenticationSource source) {
            arguments = Stream.of(source.value()).map(authFactory::authentication).toList();
        }

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return arguments.stream().map(Arguments::of);
        }
    }
}
