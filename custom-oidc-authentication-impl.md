# Writing your own OIDC `Authentication` implementation

Let's say your app security rules are not only authorities (or roles) based. Imagine a user can grant access to some resources he owns to a few other users of his choice (just like he can do to clients using OAuth2 scopes).

Imagine also, your authorization-server can provide in each token, a `grants` private claim describing who current user can proxy and what he can do on their behalf.

As we don't want application code to be aware of authorization-server private-claims details (nor duplicate private-claims parsing code), let's:
- create an `OidcToken` specialization exposing `grants` private claim (a `Map<otherUserSubject, grantIdsArray>`)
- substitute default `tokenConverter` bean with one returning instances of this new specialization
- create test annotation to populate test security context with `OidcAuthentication<CustomOidcToken>`
- demo all this wih simple `@RestController` and `@Test`

## CustomOidcToken
Let's add a method to access the grants current user was given to act on behalf of another:
``` java
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;

public class CustomOidcToken extends OidcToken {
	private static final long serialVersionUID = -958466786321575604L;

	public CustomOidcToken(Map<String, Object> claims) {
		super(claims);
	}

	@SuppressWarnings("unchecked")
	public Set<Long> getGrantIdsOnBehalfOf(String proxiedUserSubject) {
		return Optional
				.ofNullable(getClaimAsMap("proxies"))
				.flatMap(map -> Optional.ofNullable((Collection<Long>) map.get(proxiedUserSubject)))
				.map(HashSet::new)
				.map(Collections::unmodifiableSet)
				.orElse(Collections.emptySet());
	}
}
```

## Web-security configuration
All we need is replacing the default `tokenConverter` bean from `ServletSecurityBeans` with a definition of our own, building `CustomOidcToken` instead of `OidcToken`:
``` java
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.c4_soft.springaddons.security.oauth2.SynchronizedJwt2OidcTokenConverter;
import com.c4_soft.springaddons.security.oauth2.config.ServletSecurityBeans;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;

@Configuration
public class ServletSecurityBeansOverrides extends ServletSecurityBeans {
	ServletSecurityBeansOverrides(
			@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri,
			SpringAddonsSecurityProperties securityProperties) {
		super(issuerUri, securityProperties);
	}

	// token converter override
	@Override
	@Bean
	public SynchronizedJwt2OidcTokenConverter<OidcToken> tokenConverter() {
		return (var jwt) -> new CustomOidcToken(jwt.getClaims());
	}
}
```

## Test annotation
Let's copy from `@WithMockOidcAuth`.

All that has to be changed is the token implementation inside the authentication factory.

But as `grants` claim is something rather important to buisness domain, an alternative implementation would:
- define a new `@Grant` annotation to describe the proxy given by a user
- expose a `grants` attribute to `@WithCustomAuth`
- authentication factory would parse this property to set the `grants` claim in the `CustomOidcToken`:
``` java
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.annotations.AbstractAnnotatedAuthenticationBuilder;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;

@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithCustomAuth.CustomAuthFactory.class)
public @interface WithCustomAuth {

	@AliasFor("authorities")
	String[] value() default { "ROLE_USER" };

	@AliasFor("value")
	String[] authorities() default { "ROLE_USER" };

	Grant[] grants() default {};

	OpenIdClaims claims() default @OpenIdClaims();

	String bearerString() default "machin.truc.chose";

	@AliasFor(annotation = WithSecurityContext.class)
	TestExecutionEvent setupBefore() default TestExecutionEvent.TEST_METHOD;

	@Target({ ElementType.METHOD, ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	public static @interface Grant {
		String proxiedUserSubject();

		long[] proxyIds();
	}

	public static final class CustomAuthFactory extends AbstractAnnotatedAuthenticationBuilder<WithCustomAuth, OidcAuthentication<CustomOidcToken>> {
		@Override
		public OidcAuthentication<CustomOidcToken> authentication(WithCustomAuth annotation) {
			final var oidcClaims = OpenIdClaims.Token.of(annotation.claims());

			// create a copy of OIDC claim-set and add grants to it
			final Map<String, Object> allClaims = new HashMap<>(oidcClaims);
			allClaims.putAll(oidcClaims);
			allClaims.putIfAbsent("grants", new HashMap<String, Set<Long>>());
			@SuppressWarnings("unchecked")
			final var grants = (Map<String, Set<Long>>) allClaims.get("grants");
			for (final Grant grant : annotation.grants()) {
				final Set<Long> ids = new HashSet<>(grant.proxyIds().length);
				for (final Long id : grant.proxyIds()) {
					ids.add(id);
				}
				grants.put(grant.proxiedUserSubject(), ids);
			}

			return new OidcAuthentication<>(new CustomOidcToken(allClaims), authorities(annotation.authorities()), annotation.bearerString());
		}
	}
}
```
Sample usage:
``` java
@Test
@WithCustomAuth(
    authorities = { "USER", "AUTHORIZED_PERSONNEL" },
    claims = @OpenIdClaims(
        sub = "42",
        email = "ch4mp@c4-soft.com",
        emailVerified = true,
        nickName = "Tonton-Pirate",
        preferredUsername = "ch4mpy"),
    grants = {
        @Grant(proxiedSubject = "1111", value = {1, 2}),
        @Grant(proxiedSubject = "1112", value = {1})
    })
public void test() {
    ...
}
```

## Complete sample
Please refer to test sources of [`proxies-api`](https://github.com/ch4mpy/starter/tree/master/api/webmvc/proxies-api).

It contains:
- spring-boot app with security config
- `CustomOidcToken` implementation and configuration
- `GrantsController` and `UsersController` which expose REST endpoints for accessing grants and managing user proxies.
- Controller unit test decorated with `@WithCustomAuth`

You'll have to edit the test properties to point to an authorization-server providing this claim in tokens. See below to so with Keycloak and a Mapper

## Bonus: sample Keycloak mapper to add the `grants` private claim to tokens
Please refer to [`proxies-keycloak-mapper` project](https://github.com/ch4mpy/starter/tree/master/api/webmvc/proxies-keycloak-mapper).

It contains
- mapper implementation to fetch grants from a REST web-service (see test sources of [`proxies-api` project](https://github.com/ch4mpy/spring-addons/tree/master/grants-api) above)
- required META-INF files for Keycloak to load it
- maven configuration to package shaded jar