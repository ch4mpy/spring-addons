package com.c4soft.springaddons.tutorials;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Stream;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;

import com.c4_soft.springaddons.security.oauth2.test.annotations.AbstractAnnotatedAuthenticationBuilder;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;

@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = ProxiesAuth.ProxiesAuthenticationFactory.class)
public @interface ProxiesAuth {

	@AliasFor("authorities")
	String[] value() default {};

	@AliasFor("value")
	String[] authorities() default {};

	OpenIdClaims claims() default @OpenIdClaims();

	Proxy[] proxies() default {};

	String bearerString() default "machin.truc.chose";

	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore()

	default TestExecutionEvent.TEST_METHOD;

	@Target({ ElementType.METHOD, ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	public static @interface Proxy {
		String onBehalfOf();

		String[] can() default {};
	}

	public static final class ProxiesAuthenticationFactory extends AbstractAnnotatedAuthenticationBuilder<ProxiesAuth, ProxiesAuthentication> {
		@Override
		public ProxiesAuthentication authentication(ProxiesAuth annotation) {
			final var openidClaims = super.claims(annotation.claims());
			@SuppressWarnings("unchecked")
			final var proxiesClaim = (HashMap<String, List<String>>) openidClaims.getOrDefault("proxies", new HashMap<>());
			Stream.of(annotation.proxies()).forEach(proxy -> {
				proxiesClaim.put(proxy.onBehalfOf(), Stream.of(proxy.can()).toList());
			});
			openidClaims.put("proxies", proxiesClaim);

			return new ProxiesAuthentication(new ProxiesClaimSet(openidClaims), super.authorities(annotation.authorities()), annotation.bearerString());
		}
	}
}
