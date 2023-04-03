package com.c4soft.springaddons.tutorials;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;

import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.test.annotations.AbstractAnnotatedAuthenticationBuilder;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4soft.springaddons.tutorials.SecurityConfig.MyAuth;

@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMyAuth.MyAuthFactory.class)
public @interface WithMyAuth {

	@AliasFor("authorities")
	String[] value() default {};

	@AliasFor("value")
	String[] authorities() default {};

	OpenIdClaims accessClaims() default @OpenIdClaims();

	OpenIdClaims idClaims() default @OpenIdClaims();

	String accessTokenString() default "machin.truc.chose";

	String idTokenString() default "machin.bidule.chose";

	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore()

	default TestExecutionEvent.TEST_METHOD;

	@Target({ ElementType.METHOD, ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	public static @interface Proxy {
		String onBehalfOf();

		String[] can() default {};
	}

	public static final class MyAuthFactory extends AbstractAnnotatedAuthenticationBuilder<WithMyAuth, MyAuth> {
		@Override
		public MyAuth authentication(WithMyAuth annotation) {
			final var accessClaims = new OpenidClaimSet(super.claims(annotation.accessClaims()));
			final var idClaims = new OpenidClaimSet(super.claims(annotation.idClaims()));

			return new MyAuth(super.authorities(annotation.authorities()), annotation.accessTokenString(), accessClaims, annotation.idTokenString(), idClaims);
		}
	}
}
