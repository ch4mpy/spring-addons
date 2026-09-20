---
title: Resource servers
parent: spring-addons-starter-oidc
nav_order: 1
description: "Configuring a Spring Boot OAuth2 resource server from properties: authorities mapping from Keycloak roles or any other claim, authentication converter, multi-tenancy, CORS and access control."
---

# OAuth2 resource servers

As a reminder, requests to an OAuth2 resource server are authorized with access tokens validated using JWT decoders - or introspection, but which should probably avoid that because of inherent latency and scalability issues.

Resource servers only care if tokens are valid and if they should grant access to resources based on the claims associated with them. Resource servers are not concerned with how tokens are obtained. Consequently, **login and logout are not part of resource server configuration**.

## Resource Server `Security(Web)FilterChain`
If `spring-boot-starter-oauth2-resource-server` is on the classpath and unless `com.c4-soft.springaddons.oidc.resourceserver.enabled=false`, a `Security(Web)FilterChain` is created with the following default configuration:
- `@Order(Ordered.LOWEST_PRECEDENCE)` and no security matcher (acts as default, processing all requests which weren't intercepted by any other `Security(Web)FilterChain` with higher precedence)
- stateless (no session and CSRF protection disabled)
- respond with 401 to unauthorized requests
- access token introspection if `spring.security.oauth2.resourceserver.opaquetoken.introspection-uri` is set and JWT decoder otherwise
- CORS disabled (as a reminder, `cors` properties configure a global filter)
- anonymous access allowed to pre-flight requests for the path-matchers listed in `cors` properties, as well as all requests with a path matching an entry in `permit-all`; all other requests requiring a valid authentication

## Authorities Converter
Spring security implements Role Based Access Control (RBAC) with so called `GrantedAuthority` (accessed through `Authentication#getAuthorities`).

Neither OpenID nor OAuth2 include a specification for RBAC (as explained in the FAQ, scopes are not roles). About every OpenID Provider implements RBAC, but they have to use private claims for that. As each OP uses its own private claim(s), mapping OP *roles* to Spring *authorities* requires to adapt to each issuer.

By default, `spring-addons-starter-oidc` uses `ConfigurableClaimSetAuthoritiesConverter` which uses properties defined for each OP. `ByIssuerOpenidProviderPropertiesResolver`, the default resolver, uses the access token `iss` claim (*issuer*) to select which properties to provide to the authorities mapper.

For each OpenID Provider (OP), you can define as many claim groups as you like, and for each group:
- `path`: a [JSON path](https://github.com/json-path/JsonPath) to the claim(s) to be mapped as authorities. You may use tools like [https://jsonpath.com/](https://jsonpath.com/) to test your JSON path against your access tokens payload (extracted with tools like [https://jwt.io](https://jwt.io))
- `prefix`: an optional prefix to add to the OP roles (default is empty). For instance, you might add a `ROLE_` prefix to use expressions like `hasRole('admin')` instead of `hasAuthority('admin')` (provided that the role provided by the authorization server is not `ROLE_admin` already, of course).
- `caze`: optionally force roles to upper-case or lower-case (default being to keep it as provided)

Sample configuration for two different OPs:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: https://oidc.c4-soft.com/auth/realms/master
          authorities:
          - path: $.realm_access.roles
          - path: $.resource_access.*.roles
        - iss: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
          authorities:
          - path: $.cognito:groups
            prefix: EXTERNAL_
            caze: upper
```
In the above:
- for tokens with `"iss": "https://oidc.c4-soft.com/auth/realms/master"`, authorities will be mapped from *realm roles* and all available *client roles* from the token, without any transformation.
- for tokens with `"iss": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl"`, authorities will be mapped from *cognito:groups* claim, forcing it to upper-case and adding the `EXTERNAL_` prefix (`"cognito:groups": ["machin", "truc"]` will be turned into `["EXTERNAL_MACHIN", "EXTERNAL_TRUC"]`)

To use another authorities mapper, expose a `@Bean` of type `ClaimSetAuthoritiesConverter`.

To change how authorities mapping properties are resolved (for instance if you are using some "dynamic" multi-tenancy and can't know the possible issuers when writing the conf), expose a `@Bean` of type `OpenidProviderPropertiesResolver`.

## Authentication Converter
Spring Security `Authentication` is more than just a container for *authorities*: it also holds user unique identifier (`name`) and, in the case of a resource server, the access token claims. 

By default, `spring-addons-starter-oidc` uses a `(Reactive)JwtAbstractAuthenticationTokenConverter` or `(Reactive)OpaqueTokenAuthenticationConverter` implementation delegating authorities conversion to a `@Bean` in the context (see previous section). The default output are as usual:
- `JwtAuthenticationToken` when a JWT decoder is used
- `BearerTokenAuthentication` with introspection.

By exposing a custom authentication converter bean, you can use your own `Authentication` implementation. Here is a sample for a servlet with JWT decoder(s), switching to `OAuthentication<OpenidToken>` from `spring-addons-oauth2` (typed accessors to OpenID claims, `getBearerHeader()`, ...):
```java
@Bean
JwtAbstractAuthenticationTokenConverter authenticationConverter(
        Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
        OpenidProviderPropertiesResolver opPropertiesResolver) {
    return jwt -> {
        final var usernameClaim = opPropertiesResolver.resolve(jwt.getClaims())
            .orElseThrow(() -> new NotAConfiguredOpenidProviderException(jwt.getClaims()))
            .getUsernameClaim();
        final var token = new OpenidToken(jwt.getClaims(), usernameClaim, jwt.getTokenValue());
        return new OAuthentication<>(token, authoritiesConverter.convert(jwt.getClaims()));
    };
}
```
See the [`resource-server` sample](https://github.com/ch4mpy/spring-addons/tree/master/samples/resource-server) for this bean in a runnable application.

## Multi-Tenancy
Multi-tenancy is supported for resource servers with JWT decoders.

The core component for multi-tenancy is the `OpenidProviderPropertiesResolver` which is in charge of resolving the configuration properties used to build JWT decoders (and the validators embedded in it).

`ByIssuerOpenidProviderPropertiesResolver`, the default `OpenidProviderPropertiesResolver`, offers support for "static" multi-tenancy (when you know at configuration time all of the issuers you trust).

You may implement "dynamic" multi-tenancy by exposing an `OpenidProviderPropertiesResolver` bean of your own. Such a bean could, for instance, resolve the properties necessary to build new JWT decoders based on the issuer claim:
- starting with something special
- being part of specific (sub)domains
- whatever else like matching a pattern, be validated by a service querying a database, ...

As a sample, here is how you could accept tokens from any realm of a Keycloak instance, even if this realm is created after your resource server started:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: https://oidc.c4-soft.com/auth/realms/
          authorities:
          - path: $.realm_access.roles
```
```java
@Component
public class IssuerStartsWithOpenidProviderPropertiesResolver implements OpenidProviderPropertiesResolver {
    private final SpringAddonsOidcProperties properties;

    public IssuerStartsWithOpenidProviderPropertiesResolver(SpringAddonsOidcProperties properties) {
        this.properties = properties;
    }

    @Override
    public Optional<OpenidProviderProperties> resolve(Map<String, Object> claimSet) {
        final var tokenIss = Optional
            .ofNullable(claimSet.get(JwtClaimNames.ISS))
            .map(Object::toString)
            .orElseThrow(() -> new RuntimeException("Invalid token: missing issuer"));
        return properties.getOps().stream().filter(opProps -> {
            final var opBaseHref = Optional.ofNullable(opProps.getIss()).map(URI::toString).orElse(null);
            if (!StringUtils.hasText(opBaseHref)) {
                return false;
            }
            return tokenIss.startsWith(opBaseHref);
        }).findAny();
    }
}
```
That way, any token with an issuer claim starting with `https://oidc.c4-soft.com/auth/realms/` would be accepted and mapped to an `Authentication` instance using the same converter and configuration properties as any other token issued for any realm by the same Keycloak instance.

## Access Control
The default access rule is set to `isAuthenticated()` with two exceptions:
- routes matching the path-matchers listed in `permit-all` property for which anonymous requests are allowed
- pre-flight requests, unless disabled in `cors` properties (`OPTIONS` requests to routes matching the path-matchers listed in CORS properties).

The most convenient way to define fine-grained access control is probably to `@Enable(Reactive)MethodSecurity` and to decorate `@RestController` methods with `@PreAuthorize`.

For those preferring access control in configuration (or when you don't write the endpoint yourself), you can expose a `@Bean` of type `ResourceServerExpressionInterceptUrlRegistryPostProcessor` or `ResourceServerAuthorizeExchangeSpecPostProcessor`.

## CORS Configuration
Starting from version `7.8.7`, the CORS configuration is made using a global filter, the behavior of which is controlled with application properties:
```java
com:
  c4-soft:
    springaddons:
      oidc:
        cors:
        - path: /machin/**
          allowed-origin-patterns: "*"
        - path: /truc/**
          allowed-origin-patterns:
          - "http://localhost:4200"
          - "http://*.chose.com"
```
`spring-addons` CORS filter backs off if:
- CORS configuration properties are absent (no CORS properties -> no CORS filter)
- a `Cors(Web)Filter` bean is registered already in application configuration

By default, anonymous `OPTIONS` requests are allowed for all path-matchers in `cors` properties groups.

## Post-Process the Resource Server Filer-Chain
By exposing a `ResourceServer(Server)HttpSecurityPostProcessor` bean, you get complete control of the `(Server)HttpSecurity` configured in the `resourceServerSecurityFilterChain` just before it is built. This allows for changes to anything that was pre-configured.

