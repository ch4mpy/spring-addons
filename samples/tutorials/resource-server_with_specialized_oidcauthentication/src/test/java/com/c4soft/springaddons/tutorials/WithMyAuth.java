package com.c4soft.springaddons.tutorials;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;
import com.c4_soft.springaddons.security.oauth2.test.annotations.AbstractAnnotatedAuthenticationBuilder;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;

@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMyAuth.MyAuthenticationFactory.class)
public @interface WithMyAuth {

	@AliasFor("authorities")
	String[] value() default { "ROLE_USER" };

	@AliasFor("value")
	String[] authorities() default { "ROLE_USER" };

	OpenIdClaims claims() default @OpenIdClaims();

	Proxy[] proxies() default {};

	String bearerString() default "machin.truc.chose";

	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	@Target({ ElementType.METHOD, ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	public static @interface Proxy {
		String onBehalfOf();

		String[] can() default {};
	}

	public static final class MyAuthenticationFactory extends AbstractAnnotatedAuthenticationBuilder<WithMyAuth, MyAuthentication> {
		@Override
		public MyAuthentication authentication(WithMyAuth annotation) {
			final var claims = super.claims(annotation.claims());
			final var token = new OidcToken(claims);
			final var proxies =
					Stream
							.of(annotation.proxies())
							.collect(
									Collectors
											.toMap(
													Proxy::onBehalfOf,
													p -> new com.c4soft.springaddons.tutorials.Proxy(
															p.onBehalfOf(),
															token.getSubject(),
															Stream.of(p.can()).toList())));
			return new MyAuthentication(token, super.authorities(annotation.authorities()), proxies, annotation.bearerString());
		}
	}
}