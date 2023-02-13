# Authentication containing data from both the access token and a custom header

## 1. Overview
For this tutorial, we will assume that in addition to to a JWT **access token** provided as `Authorization` header, a `X-ID-Token` header is provided with a JWT **ID token**.

Be sure your environment meets [tutorials prerequisits](https://github.com/ch4mpy/spring-addons/blob/master/samples/tutorials/README.md#prerequisites).

## 2. Project Initialization
We'll start a spring-boot 3 project with the help of https://start.spring.io/
Following dependencies will be needed:
- lombok
- actuator

Then add dependencies to spring-addons:
```xml
		<dependency>
			<groupId>org.springframework.security</groupId>
			<artifactId>spring-security-config</artifactId>
		</dependency>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<!-- use spring-addons-webflux-jwt-resource-server instead for reactive apps -->
			<artifactId>spring-addons-webmvc-jwt-resource-server</artifactId>
			<version>6.0.12</version>
		</dependency>
		<dependency>
			<groupId>com.c4-soft.springaddons</groupId>
			<!-- use spring-addons-webflux-test instead for reactive apps -->
			<artifactId>spring-addons-webmvc-jwt-test</artifactId>
			<version>6.0.12</version>
			<scope>test</scope>
		</dependency>
```

`spring-addons-webmvc-jwt-resource-server` internally uses `spring-boot-starter-oauth2-resource-server` and adds the following:
- Authorities mapping from token attribute(s) of your choice (with prefix and case processing)
- CORS configuration
- stateless session management (no servlet session, user "session" state in access-token only)
- disabled CSRF (no servlet session)
- 401 (unauthorized) instead of 302 (redirect to login) when authentication is missing or invalid on protected end-point
- list of routes accessible to unauthorized users (with anonymous enabled if this list is not empty)
all that from properties only

## 3. Web-Security Configuration
This configuration will use the pretty convenient `com.c4_soft.springaddons.security.oauth2.config.synchronised.HttpServletRequestSupport` which provides tooling to access the current request, and in our case, its headers. If we were writing a webflux application, we'd use is reactive pendant: `com.c4_soft.springaddons.security.oauth2.config.reactive.ServerHttpRequestSupport`.

`spring-oauth2-addons` comes with `@AutoConfiguration` for web-security config adapted to REST API projects. We'll just add:
- `@EnableMethodSecurity` to activate `@PreAuthorize` on components methods.
- create an authentication of our own designed to hold ID token string and claims in addition to access token ones: `MyAuth`
```java
@Data
@EqualsAndHashCode(callSuper = true)
public static class MyAuth extends OAuthentication<OpenidClaimSet> {
	private static final long serialVersionUID = 1734079415899000362L;
	private final String idTokenString;
	private final OpenidClaimSet idClaims;

	public MyAuth(Collection<? extends GrantedAuthority> authorities, String accessTokenString,
			OpenidClaimSet accessClaims, String idTokenString, OpenidClaimSet idClaims) {
		super(accessClaims, authorities, accessTokenString);
		this.idTokenString = idTokenString;
		this.idClaims = idClaims;
	}

}
```
- provide an `OAuth2AuthenticationFactory` bean to switch `Authentication` implementation from `JwtAuthenticationToken` to our `MyAuth`
```java
@Bean
OAuth2AuthenticationFactory authenticationFactory(
		Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
		JwtDecoder jwtDecoder) {
	return (accessBearerString, accessClaims) -> {
		try {
			final var authorities = authoritiesConverter.convert(accessClaims);
			final var idTokenString = HttpServletRequestSupport.getUniqueHeader(ID_TOKEN_HEADER_NAME);
			final var idToken = jwtDecoder.decode(idTokenString);

			return new MyAuth(authorities, accessBearerString, new OpenidClaimSet(accessClaims), idTokenString,
					new OpenidClaimSet(idToken.getClaims()));
		} catch (JwtException e) {
			throw new InvalidHeaderException(ID_TOKEN_HEADER_NAME);
		}
	};
}
```
- define access control rules to actuator endpoints:
```java
@Bean
ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
	// @formatter:off
    return (AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) -> registry
            .requestMatchers(HttpMethod.GET, "/actuator/**").hasAuthority("OBSERVABILITY:read")
            .requestMatchers("/actuator/**").hasAuthority("OBSERVABILITY:write")
            .anyRequest().authenticated();
    // @formatter:on
}
```

## 4. Application Properties 
`application.yaml` with profiles for various OpenID providers:
```yaml
server:
  error.include-message: always

spring:
  lifecycle.timeout-per-shutdown-phase: 30s
  security.oauth2.resourceserver.jwt.issuer-uri: https://localhost:8443/realms/master

com:
  c4-soft:
    springaddons:
      security:
        issuers:
          - location: ${spring.security.oauth2.resourceserver.jwt.issuer-uri}
            authorities:
              claims:
                - realm_access.roles
                - resource_access.spring-addons-public.roles
                - resource_access.spring-addons-confidential.roles
              caze: upper
              prefix: ROLE_
        cors:
          - path: /greet
        permit-all:
        - /actuator/health/**
        - /v3/api-docs
        - /v3/api-docs/**

management:
  endpoint:
    health.probes.enabled: true
  health:
    readinessstate.enabled: true
    livenessstate.enabled: true
  endpoints:
    web.exposure.include: "*"

---
spring.config.activate.on-profile: cognito
spring.security.oauth2.resourceserver.jwt.issuer-uri: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
com.c4-soft.springaddons.security.issuers:
  - location: ${spring.security.oauth2.resourceserver.jwt.issuer-uri}
    authorities:
      claims: 
        - cognito:groups
      caze: upper
      prefix: ROLE_

---
spring.config.activate.on-profile: auth0
com.c4-soft.springaddons.security.issuers:
  - location: https://dev-ch4mpy.eu.auth0.com/
    authorities:
      claims:
        - roles
        - permissions
      caze: upper
      prefix: ROLE_
```

## 5. Sample `@RestController`
Please note that OpenID standard claims can be accessed with getters (instead of Map<String, Object> like with JwtAuthenticationToken for instance)
``` java
@RestController
@PreAuthorize("isAuthenticated()")
public class GreetingController {

    @GetMapping("/greet")
    public String getGreeting(MyAuth auth) {
        return "Hi %s! You are granted with: %s.".formatted(
                auth.getIdClaims().getEmail(), // From ID token in X-ID-Token header
                auth.getAuthorities()); // From access token in Authorization header
    }
}
```

## 6. Conclusion
This sample was guiding you to build a servlet application (webmvc) with security data extracted from both access token and a custom header.

For a reactive application (webflux), the main differences would be:
- using `spring-addons-webflux-jwt-resource-server` as dependency (instead of `spring-addons-webmvc-jwt-resource-server`)
- retrieve ID token from headers using `ServerHttpRequestSupport` instead of `HttpServletRequestSupport`
