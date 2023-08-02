# Authentication containing data from both the access token and a custom header

## 0. Disclaimer
There are quite a few samples, and all are part of CI to ensure that source compile and all tests pass. Unfortunately, this README is not automatically updated when source changes. Please use it as a guidance to understand the source. **If you copy some code, be sure to do it from the source, not from this README**.

## 1. Overview
For this tutorial, we will assume that in addition to to a JWT **access token** in the `Authorization` header, the OAuth2 client provides with a JWT **ID token** in a `X-ID-Token` header.

Be sure your environment meets [tutorials prerequisits](https://github.com/ch4mpy/spring-addons/blob/master/samples/tutorials/README.md#prerequisites).

## 2. Project Initialization
We'll start a spring-boot 3 project with the help of https://start.spring.io/
Following dependencies will be needed:
- Spring Web
- OAuth2 Resource Server
- Lombok

Then add dependencies to:
- [`spring-addons-webmvc-jwt-resource-server`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-jwt-resource-server/6.1.5)
- [`spring-addons-webmvc-jwt-test`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-jwt-test/6.1.5) with `test` scope
```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-oidc</artifactId>
    <version>${spring-addons.version}</version>
</dependency>
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-oidc-test</artifactId>
    <version>${spring-addons.version}</version>
    <scope>test</scope>
</dependency>
```

If for whatever reason you don't want to use `spring-addons-starter-oidc`, see [`servlet-resource-server`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/servlet-resource-server) or [`reactive-resource-server`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/reactive-resource-server) for basic configuration with `spring-boot-starter-oauth2-resource-server`. Spoiler, it is quite more verbose and error prone.

## 3. Web-Security Configuration
This configuration will use the pretty convenient [`com.c4_soft.springaddons.security.oauth2.config.synchronised.HttpServletRequestSupport`](https://github.com/ch4mpy/spring-addons/blob/master/webmvc/spring-addons-webmvc-core/src/main/java/com/c4_soft/springaddons/security/oauth2/config/synchronised/HttpServletRequestSupport.java) which provides tooling to access the current request, and in our case, its headers. If we were writing a WebFlux application, we'd use is reactive equivalent: [`com.c4_soft.springaddons.security.oauth2.config.reactive.ServerHttpRequestSupport`](https://github.com/ch4mpy/spring-addons/blob/master/webflux/spring-addons-webflux-core/src/main/java/com/c4_soft/springaddons/security/oauth2/config/reactive/ServerHttpRequestSupport.java). If you don't use `spring-addons-starter-oidc`, you might need to copy some code from one of this support classes.

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
- provide a `JwtAbstractAuthenticationTokenConverter` bean to switch `Authentication` implementation from `JwtAuthenticationToken` to our `MyAuth`

```java
public static final String ID_TOKEN_HEADER_NAME = "X-ID-Token";
private static final Map<String, JwtDecoder> idTokenDecoders = new ConcurrentHashMap<>();

private JwtDecoder getJwtDecoder(Map<String, Object> accessClaims) {
	if (accessClaims == null) {
		return null;
	}
	final var iss = Optional.ofNullable(accessClaims.get(JwtClaimNames.ISS)).map(Object::toString).orElse(null);
	if (iss == null) {
		return null;
	}
	if (!idTokenDecoders.containsKey(iss)) {
		idTokenDecoders.put(iss, JwtDecoders.fromIssuerLocation(iss));
	}
	return idTokenDecoders.get(iss);
}

@BeanJwtAbstractAuthenticationTokenConverter jwtAuthenticationConverter(Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
	return jwt -> {
		try {
			final var jwtDecoder = getJwtDecoder(jwt.getClaims());
			final var authorities = authoritiesConverter.convert(jwt.getClaims());
			final var idTokenString = HttpServletRequestSupport.getUniqueHeader(ID_TOKEN_HEADER_NAME);
			final var idToken = jwtDecoder == null ? null : jwtDecoder.decode(idTokenString);

			return new MyAuth(
					authorities,
					jwt.getTokenValue(),
					new OpenidClaimSet(jwt.getClaims()),
					idTokenString,
					new OpenidClaimSet(idToken.getClaims()));
		} catch (JwtException e) {
			throw new InvalidHeaderException(ID_TOKEN_HEADER_NAME);
		}
	};
}
```

If you don't use `spring-addons-starter-oidc`, you'll have to provide the authentication converter (or an authentication manager resolver) when configuring `http.resourceServer()`.

## 4. Application Properties 
Nothing really special here, just the usual Spring Boot and spring-addons configuration (accepting identities from 3 different trusted issuers):
```yaml
scheme: http
origins: ${scheme}://localhost:4200
keycloak-port: 8442
keycloak-issuer: ${scheme}://localhost:${keycloak-port}/realms/master
cognito-issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
auth0-issuer: https://dev-ch4mpy.eu.auth0.com/

server:
  error:
    include-message: always
  ssl:
    enabled: false

spring:
  lifecycle:
    timeout-per-shutdown-phase: 30s

com:
  c4-soft:
    springaddons:
      oidc:
        cors:
        - path: /**
          allowed-origins: ${origins}
        issuers:
        - location: ${keycloak-issuer}
          username-claim: preferred_username
          authorities:
          - path: $.realm_access.roles
          - path: $.resource_access.*.roles
        - location: ${cognito-issuer}
          username-claim: username
          authorities:
          - path: cognito:groups
        - location: ${auth0-issuer}
          username-claim: $['https://c4-soft.com/user']['name']
          authorities:
          - path: $['https://c4-soft.com/user']['roles']
          - path: $.permissions

---
scheme: https
keycloak-port: 8443

server:
  ssl:
    enabled: true

spring:
  config:
    activate:
      on-profile: ssl
```

## 5. Sample `@RestController`
Please note that OpenID standard claims can be accessed with getters (instead of Map<String, Object> like with JwtAuthenticationToken for instance)
``` java
@RestController
@PreAuthorize("isAuthenticated()")
public class GreetingController {

	@GetMapping("/greet")
	public MessageDto getGreeting(MyAuth auth) {
		return new MessageDto(
				"Hi %s! You are granted with: %s.".formatted(
						auth.getIdClaims().getEmail(), // From ID token in X-ID-Token header
						auth.getAuthorities())); // From access token in Authorization header
	}

	static record MessageDto(String body) {
	}
}
```

## 6. Conclusion
This sample was guiding you to build a servlet application (webmvc) with security data extracted from both access token and a custom header.

For a reactive application (webflux), the main differences would be:
- using `spring-addons-webflux-jwt-resource-server` as dependency (instead of `spring-addons-webmvc-jwt-resource-server`)
- retrieve ID token from headers using `ServerHttpRequestSupport` instead of `HttpServletRequestSupport`
