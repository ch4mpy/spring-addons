package com.c4_soft.springaddons.security.oauth2.test.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;

import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;

@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMockOAuth2Auth.OAuth2AuthenticationTokenFactory.class)
public @interface WithMockOAuth2Auth {

	@AliasFor("authorities")
	String[] value() default {  };

	@AliasFor("value")
	String[] authorities() default {  };

	OpenIdClaims claims() default @OpenIdClaims();

	String tokenString() default "machin.truc.chose";

	String authorizedClientRegistrationId() default "bidule";

	/**
	 * @return if true OAuth2AuthenticationToken principal is DefaultOidcUser, otherwise, is DefaultOAuth2User is used
	 */
	boolean isPrincipalOidc() default true;

	/**
	 * @return the key used to access the user's &quot;name&quot; from claims
	 */
	String nameAttributeKey() default "sub";

	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	public static final class OAuth2AuthenticationTokenFactory
			extends AbstractAnnotatedAuthenticationBuilder<WithMockOAuth2Auth, OAuth2AuthenticationToken> {
		@Override
		public OAuth2AuthenticationToken authentication(WithMockOAuth2Auth annotation) {
			final var token = new OpenidClaimSet(super.claims(annotation.claims()));
			final var authorities = super.authorities(annotation.authorities());
			final var principal = annotation.isPrincipalOidc()
					? new DefaultOidcUser(authorities,
							new OidcIdToken(annotation.tokenString(), token.getIssuedAt(), token.getExpiresAt(), token))
					: new DefaultOAuth2User(authorities, token, annotation.nameAttributeKey());

			return new OAuth2AuthenticationToken(principal, authorities, annotation.authorizedClientRegistrationId());
		}
	}
}
