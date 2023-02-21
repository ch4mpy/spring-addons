# Configure an OAuth2 REST API with Spring Boot 3

## 1. Overview
In this tutorial, we'll build web security configuration  for an OAuth2  REST API with Spring Boot 3 and see how to make it generic enough to support about any OIDC authorization-server and multiple environments.

Be sure your development environment meets [tutorials prerequisites](https://github.com/ch4mpy/spring-addons/blob/master/samples/tutorials/README.md#prerequisites).

## 2. Project Initialization
We'll initiate a spring-boot 3.0.2 project with the help of https://start.spring.io/
Following dependencies will be needed:
- Spring Web
- OAuth2 Resource Server
- Spring Boot Actuator
- lombok

We'll also need 
- `org.springdoc`:`springdoc-openapi-starter-webmvc-ui`:`2.0.2`
- `org.springframework.security`:`spring-security-test` with `test` scope

## 3. Web-Security Configuration With `spring-boot-starter-oauth2-resource-server`
What we'll write in this section is pretty verbose. The reader only interested in the leanest possible solution would skip it and refer directly to the [next section](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_jwtauthenticationtoken#4-configuration-simplification).

### 3.1. Preamble
A few specs for a REST API web security config:
- enable and configure CORS
- stateless session management (no servlet session, user "session" state in access-token only)
- disabled CSRF (safe because there is no servlet session)
- enable anonymous and allow public access to a few resources
- non "public" routes require users to be authenticated, fine grained access-control being achieved with method-security (`@PreAuthrorize` and alike)
- return 401 instead of redirecting to login

We'll start building our Spring Boot 3 security configuration from this base:
```java
@EnableWebSecurity
@EnableMethodSecurity
@Configuration
public class WebSecurityConfig {
    // As we need more than one converter, define aliases
    interface Jwt2AuthoritiesConverter extends Converter<Jwt, Collection<? extends GrantedAuthority>> {}
    interface Jwt2AuthenticationConverter extends Converter<Jwt, JwtAuthenticationToken> {}
}
```

### 3.2. Configuration Properties
There are a few things we want to configure from application properties to bring enough flexibility:
- trusted issuers
- authorities mapping (source claim(s), prefix and case processing), per issuer
- claim to use for user name, per issuer
- fine grained CORS configuration (origin, headers, methods, etc.), per path-matcher
- routes accessible to anonymous

The final YAML file should include something like that:
```yaml
com:
  c4-soft:
    springaddons:
      security:
        cors:
        - path: /**
          allowed-origins: http://localhost:4200
        issuers:
        - location: http://localhost:8442/realms/master
          username-claim: preferred_username
          authorities:
            claims:
            - realm_access.roles
            - resource_access.spring-addons-public.role
            - resource_access.spring-addons-confidential.roles
        permit-all: 
        - "/actuator/health/readiness"
        - "/actuator/health/liveness"
        - "/v3/api-docs/**"
```

To parse this conf, we'll define those `@ConfigurationProperties`:
```java
@Data
@Configuration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.security")
public static class SpringAddonsSecurityProperties {
    private CorsProperties[] cors = {};
    private IssuerProperties[] issuers = {};
    private String[] permitAll = {};

    @Data
    public static class CorsProperties {
        private String path;
        private String[] allowedOrigins = { "*" };
        private String[] allowedMethods = { "*" };
        private String[] allowedHeaders = { "*" };
        private String[] exposedHeaders = { "*" };
    }

    @Data
    public static class IssuerProperties {
        private URI location;
        private URI jwkSetUri;
        private SimpleAuthoritiesMappingProperties authorities = new SimpleAuthoritiesMappingProperties();
        private String usernameClaim = StandardClaimNames.SUB;
    }

    @Data
    public static class SimpleAuthoritiesMappingProperties {
        private String[] claims = { "realm_access.roles" };
        private String prefix = "";
        private Case caze = Case.UNCHANGED;
    }

    public static enum Case {
        UNCHANGED, UPPER, LOWER
    }

    public IssuerProperties getIssuerProperties(String iss) throws NotATrustedIssuerException {
        return Stream.of(issuers)
                .filter(issuerProps -> Objects.equals(
                        Optional.ofNullable(issuerProps.getLocation()).map(URI::toString).orElse(null),
                        iss))
                .findAny().orElseThrow(
                        () -> new NotATrustedIssuerException(iss));
    }

    public IssuerProperties getIssuerProperties(Object iss) throws NotATrustedIssuerException {
        if (iss == null && issuers.length == 1) {
            return issuers[0];
        }
        return getIssuerProperties(Optional.ofNullable(iss).map(Object::toString).orElse(null));
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public static final class NotATrustedIssuerException extends RuntimeException {
        public NotATrustedIssuerException(String iss) {
            super("%s is not configured as trusted issuer".formatted(iss));
        }
    }
}
```

### 3.3. Authorities Converter
As a reminder, the `scope` of a token defines what a resource-owner allowed an OAuth2 client to do on his behalf, when "roles" are a way to represent what a resource-owner is allowed to do on resource-servers.

RBAC is a very common pattern for access-control, but neither OAuth2 nor OpenID define a standard representation for "roles". Each vendor implements it with its own private-claim(s) and Spring Security default authorities mapper (which maps from the `scope` claim, adding the `SCOPE_` prefix) won't satisfy to our needs, unless we twisted the usage of the `scope` claim on the authorization-server to contain user roles, off course.

So, we need a converter to extract spring-security `GrantedAuthority` collection from claim(s) of our choice. In a first iteration, we'll use Keycloak `realm_access.roles` claim as source for authorities:
```java
@SuppressWarnings("unchecked")
@Bean
Jwt2AuthoritiesConverter authoritiesConverter() {
    return jwt -> {
        final var realmAccess = (Map<String, Object>) jwt.getClaims().getOrDefault("realm_access", Map.of());
        final var realmRoles = (Collection<String>) realmAccess.getOrDefault("roles", List.of());
        return realmRoles.stream().map(SimpleGrantedAuthority::new).toList();
    };
}
```

This implementation has serious limitations: if client-roles mapping is activated in Keycloak, reading just `realm_access.roles` claim is not enough. We should also parse `resource_access.{client-id}.roles`, with substitution of the ID for each client with client-roles mapping activated.

Also, if the authorization-server was anything else than Keycloak, the private-claim(s) used to store roles would probably be different.

Here is a way to define an authorities converter from a configurable list of claims:
```java
@SuppressWarnings("unchecked")
@Bean
Jwt2AuthoritiesConverter authoritiesConverter(@Value("${authorities-converter.claims}") String[] authoritiesClaims) {
    return jwt -> Stream.of(authoritiesClaims)
        .flatMap(rolesPath -> getRoles(jwt.getClaims(), rolesPath))
        .map(SimpleGrantedAuthority::new)
        .collect(Collectors.toSet());
}

@SuppressWarnings("unchecked")
private static Stream<String> getRoles(Map<String, Object> claims, String rolesPath) {
    final var claimsToWalk = rolesPath.split("\\.");
    var i = 0;
    var obj = Optional.of(claims);
    while (i++ < claimsToWalk.length) {
        final var claimName = claimsToWalk[i - 1];
        if (i == claimsToWalk.length) {
            return obj.map(o -> (List<Object>) o.get(claimName)).orElse(List.of()).stream().map(Object::toString);
        }
        obj = obj.map(o -> (Map<String, Object>) o.get(claimName));
    }
    return Stream.empty();
}
```

**Cool, we can now map authorities from any OAuth2 access-token, issued by any authorization-server, by just editing a configuration property!**

Let's polish it by adding the possibility to configure a prefix and case transformation:
```java
@Bean
Jwt2AuthoritiesConverter authoritiesConverter(SpringAddonsSecurityProperties addonsProperties) {
    // @formatter:off
    return jwt -> {
        final var issuerProps = addonsProperties.getIssuerProperties(jwt.getIssuer());
        return Stream.of(issuerProps.getAuthorities().getClaims())
                .flatMap(rolesPath -> getRoles(jwt.getClaims(), rolesPath))
                .map(role -> "%s%s".formatted(issuerProps.getAuthorities().getPrefix(), role))
                .map(role -> processCase(role, issuerProps.getAuthorities().getCaze()))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    };
    // @formatter:on
}

private static String processCase(String role, Case caze) {
    switch (caze) {
    case UPPER: {
        return role.toUpperCase();
    }
    case LOWER: {
        return role.toLowerCase();
    }
    default:
        return role;
    }
}
```

### 3.4. Authentication Converter Versus `AuthenticationManagerResolver`
As we already defined a powerful authorities converter, defining an authentication converter is trivial:
```java
@Bean
Jwt2AuthenticationConverter authenticationConverter(
        Converter<Jwt, Collection<? extends GrantedAuthority>> authoritiesConverter,
        SpringAddonsSecurityProperties addonsProperties) {
    return jwt -> new JwtAuthenticationToken(
            jwt,
            authoritiesConverter.convert(jwt),
            jwt.getClaimAsString(addonsProperties.getIssuerProperties(jwt.getIssuer()).getUsernameClaim()));
}
```

 This is would be just enough if we need to accept identities from a single issuer, but for multi-tenant scenarios, we should override the `AuthenticationManagerResolver` too, so that the `JwtDecoder`, as well as authorities and authentication converters, match the access-token issuer:
```java
@Bean
JwtIssuerAuthenticationManagerResolver authenticationManagerResolver(
        OAuth2ResourceServerProperties auth2ResourceServerProperties,
        SpringAddonsSecurityProperties addonsProperties,
        Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter) {
    final Map<String, AuthenticationManager> jwtManagers = Stream.of(addonsProperties.getIssuers())
            .collect(Collectors.toMap(issuer -> issuer.getLocation().toString(), issuer -> {
                JwtDecoder decoder = issuer.getJwkSetUri() != null
                        && StringUtils.hasLength(issuer.getJwkSetUri().toString())
                                ? NimbusJwtDecoder.withJwkSetUri(issuer.getJwkSetUri().toString()).build()
                                : JwtDecoders.fromIssuerLocation(issuer.getLocation().toString());
                var provider = new JwtAuthenticationProvider(decoder);
                provider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
                return provider::authenticate;
            }));

    return new JwtIssuerAuthenticationManagerResolver((AuthenticationManagerResolver<String>) jwtManagers::get);
}
```

### 3.5. CORS Configuration
Spring's `CorsConfigurationSource` allows us to fine tune `CorsConfiguration` for as many path-matchers as we like. Let's parse our configuration properties to create such a CORS configuration source:
```java
private CorsConfigurationSource corsConfigurationSource(SpringAddonsSecurityProperties addonsProperties) {
    final var source = new UrlBasedCorsConfigurationSource();
    for (final var corsProps : addonsProperties.getCors()) {
        final var configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(corsProps.getAllowedOrigins()));
        configuration.setAllowedMethods(Arrays.asList(corsProps.getAllowedMethods()));
        configuration.setAllowedHeaders(Arrays.asList(corsProps.getAllowedHeaders()));
        configuration.setExposedHeaders(Arrays.asList(corsProps.getExposedHeaders()));
        source.registerCorsConfiguration(corsProps.getPath(), configuration);
    }
    return source;
}
```
**Great! when switching environments, we can can now easily adapt CORS mapping.** For instance, allowed origin could be https://localhost:4200, https://dev.myapp.pf or https://www.myapp.pf depending on where we deploy.

### 3.6. Security Filter-Chain
Now that we have all the required beans at hand, let's assemble the security filter-chain
```java
@Bean
SecurityFilterChain filterChain(
        HttpSecurity http,
        ServerProperties serverProperties,
        SpringAddonsSecurityProperties addonsProperties,
        AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) throws Exception {

    http.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(authenticationManagerResolver));

    // Enable anonymous
    http.anonymous();

    // Enable and configure CORS
    if (addonsProperties.getCors().length > 0) {
        http.cors().configurationSource(corsConfigurationSource(addonsProperties));
    } else {
        http.cors().disable();
    }

    // State-less session (state in access-token only)
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    // Disable CSRF because of state-less session-management
    http.csrf().disable();

    // Return 401 (unauthorized) instead of 302 (redirect to login) when
    // authorization is missing or invalid
    http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
        response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Restricted Content\"");
        response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
    });

    // If SSL enabled, disable http (https only)
    if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
        http.requiresChannel().anyRequest().requiresSecure();
    }

    // Route security: authenticated to all routes but actuator and Swagger-UI
    // @formatter:off
    http.authorizeHttpRequests()
        .requestMatchers(addonsProperties.getPermitAll()).permitAll()
        .anyRequest().authenticated();
    // @formatter:on

    return http.build();
}
```

## 4. Configuration Simplification
What we achieved so far is pretty flexible but also quite verbose and we'd certainly avoid duplicating it in many micro-services. An option would be to put all this code in a library and, maybe, make it a Spring Boot starter for those beans to be auto-magically instantiated.

### 4.1. `spring-addons-webmvc-jwt-resource-server`
The good news is such starters already exist: by replacing `spring-boot-starter-oauth2-resource-server` with `com.c4-soft.springaddons`:`spring-addons-webmvc-jwt-resource-server`, we can shrink web-security configuration to almost nothing, while keeping the exact same features and portability:
```java
@Configuration
@EnableMethodSecurity
public static class WebSecurityConfig {
}
```
**No, nothing more is needed! All is auto-configured based on what is already present in application properties.** You can browse a complete sample [there](https://github.com/ch4mpy/spring-addons/tree/master/samples/webmvc-jwt-oauthentication). What happens under the hood is what we detailed in the [previous section](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_jwtauthenticationtoken#3-web-security-configuration-with-spring-boot-starter-oauth2-resource-server).

Bootyful, isn't it?

### 4.2. Accept Identities From Different OIDC Vendors
To demo how portable the configuration we built is, let's update out properties to **accept identities issued by a local Keycloak instance as well as remote Cognito and Auth0 ones, all having different source claims for authorities and user name**:
```yaml
com:
  c4-soft:
    springaddons:
      security:
        cors:
        - path: /**
          allowed-origins: http://localhost:4200
        issuers:
        - location: http://localhost:8442/realm/master
          username-claim: preferred_username
          authorities:
            claims:
            - realm_access.roles
            - resource_access.spring-addons-public.role
            - resource_access.spring-addons-confidential.roles
        - location: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
          username-claim: username
          authorities:
            claims: 
            - cognito:groups
        - location: https://dev-ch4mpy.eu.auth0.com/
          username-claim: email
          authorities:
            claims: 
            - roles
            - permissions
        permit-all: 
        - "/actuator/health/readiness"
        - "/actuator/health/liveness"
        - "/v3/api-docs/**"
```
And with the usage of Spring profiles, we could adapt `allowed-origins` or `location` URIs according to where we deploy.

## 5. Conclusion
This sample was guiding you to build a very flexible security configuration for a servlet resource-server with JWT decoder. To configure a webflux resource-server or use access-token introspection instead of JWT decoding, or using custom `Authentication` implementations, please refer to [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples).

You might also explore source code to have a look at how to mock identities in unit and integration tests and assert  access-control is behaving as expected. All samples and tutorials include detailed access-control tests.
