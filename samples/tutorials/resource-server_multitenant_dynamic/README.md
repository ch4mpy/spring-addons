# How to configure a Spring REST API dynamic tenants
Sample of advanced customization of spring-addons auto-configuration: in this tutorial, the resource server should accept access tokens issued by any issuer hosted on a list of servers we trust (for instance dynamically generated Keycloak realms). For that, we'll customize the way issuer properties are resolved and also modify the authentication manager resolver to create a new authentication manager for each new issuer hosted on a server we trust.

## 0. Disclaimer
There are quite a few samples, and all are part of CI to ensure that sources compile and all tests pass. Unfortunately, this README is not automatically updated when source changes. Please use it as a guidance to understand the source. **If you copy some code, be sure to do it from the source, not from this README**.

## 1. Prerequisites
We assume that [tutorials main README prerequisites section](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#prerequisites) has been achieved and that you have a minimum of 1 OIDC Provider (2 would be better) with ID and secret for clients configured with authorization-code flow.

## 2. Project Initialization
We'll be starting where the [`resource-server_with_oauthentication` tutorial](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_oauthentication) ends. Make sure you have this project running before you start.

## 3. Web-Security Configuration
We can't anticipate issuer URIs path, but we do know the base URIs (scheme, host and port) for the issuers we should trust.

So, for this project we need to change:
- how issuers configuration is resolved. We'll assume that the configuration (authorities and username mapping) is the same for all issuers of the same server
- how authentication managers are resolved

For that, let's first define a function providing with the base URI (scheme, host and port) of an issuer:
```java
private static URI baseUri(URI uri) {
	if (uri == null) {
		return null;
	}
	try {
		return new URI(uri.getScheme(), null, uri.getHost(), uri.getPort(), null, null, null);
	} catch (URISyntaxException e) {
		throw new InvalidIssuerException(uri.toString());
	}
}

@ResponseStatus(code = HttpStatus.UNAUTHORIZED)
static class InvalidIssuerException extends RuntimeException {
	private static final long serialVersionUID = 4431133205219303797L;

	public InvalidIssuerException(String issuerUriString) {
		super("Issuer %s is not trusted".formatted(issuerUriString));
	}
}
```
Then, let's override how issuer configuration properties are resolved:
```java
@Primary
@Component
static class DynamicTenantProperties extends SpringAddonsSecurityProperties {

	@Override
	public IssuerProperties getIssuerProperties(String iss) throws MissingAuthorizationServerConfigurationException {
		return super.getIssuerProperties(baseUri(URI.create(iss)).toString());
	}

}
```
Last, we need an authentication manager resolver which just checks that a token issuer is hosted on a server we trust and returning an authentication manager with a JWT decoder for unpredictable issuers:
```java
@Component
static class DynamicTenantsAuthenticationManagerResolver implements AuthenticationManagerResolver<HttpServletRequest> {
	private final Set<String> issuerBaseUris;
	private final Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter;
	private final Map<String, JwtAuthenticationProvider> jwtManagers = new ConcurrentHashMap<>();
	private final JwtIssuerAuthenticationManagerResolver delegate =
			new JwtIssuerAuthenticationManagerResolver((AuthenticationManagerResolver<String>) this::getAuthenticationManager);

	public DynamicTenantsAuthenticationManagerResolver(
			SpringAddonsSecurityProperties addonsProperties,
			Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter) {
		this.issuerBaseUris = Stream.of(addonsProperties.getIssuers()).map(IssuerProperties::getLocation).map(WebSecurityConfig::baseUri).map(URI::toString)
				.collect(Collectors.toSet());
		this.jwtAuthenticationConverter = jwtAuthenticationConverter;
	}

	@Override
	public AuthenticationManager resolve(HttpServletRequest context) {
		return delegate.resolve(context);
	}

	public AuthenticationManager getAuthenticationManager(String issuerUriString) {
		final var issuerBaseUri = baseUri(URI.create(issuerUriString)).toString();
		if (!issuerBaseUris.contains(issuerBaseUri)) {
			throw new InvalidIssuerException(issuerUriString);
		}
		if (!this.jwtManagers.containsKey(issuerUriString)) {
			this.jwtManagers.put(issuerUriString, getProvider(issuerUriString));
		}
		return jwtManagers.get(issuerUriString)::authenticate;
	}

	private JwtAuthenticationProvider getProvider(String issuerUriString) {
		var provider = new JwtAuthenticationProvider(JwtDecoders.fromIssuerLocation(issuerUriString));
		provider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
		return provider;
	}
}
```

## 4. Application Properties
The application properties from [`resource-server_with_oauthentication`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_oauthentication) need an edit: we need base URIs of the servers hosting issuers instead of issuers itself:
```yaml
scheme: http
origins: ${scheme}://localhost:4200
keycloak-port: 8442

server:
  error:
    include-message: always
  ssl:
    enabled: false

com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: ${scheme}://localhost:${keycloak-port}
          username-claim: preferred_username
          authorities:
          - path: $.realm_access.roles
          - path: $.resource_access.*.roles
        - iss: https://cognito-idp.us-west-2.amazonaws.com
          username-claim: username
          authorities:
          - path: cognito:groups
        - iss: https://dev-ch4mpy.eu.auth0.com
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
No change, just keep the one from [`resource-server_with_oauthentication`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_oauthentication)

## 5. Unit-Tests
No change, just keep the one from [`resource-server_with_oauthentication`](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_oauthentication)

## 6. Conclusion
Et voilà! We can now query our API with access tokens issued for any realm of our Keycloak instance (and got to see in action `spring-addons-starter-oidc` versatility)
