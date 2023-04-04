# Configure an OAuth2 REST API with Spring Boot 3
This introduction tutorial is not maintained anymore. It is kept because of external links pointing to it and has been replaced with:
- [servlet-resource-server](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/servlet-resource-server) using only Spring Boot "official" starter
- [webmvc-jwt-default](https://github.com/ch4mpy/spring-addons/tree/master/samples/webmvc-jwt-default) using only spring-addons starter
- [reactive-resource-server](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/reactive-resource-server) using only Spring Boot "official" starter
- [webflux-jwt-default](https://github.com/ch4mpy/spring-addons/tree/master/samples/webflux-jwt-default) using only spring-addons starter

## 1. Overview
In this tutorial, we'll build web security configuration  for an OAuth2  REST API with Spring Boot 3 and see how to make it generic enough to support about any OIDC authorization-server and multiple environments.

Be sure your development environment meets [tutorials prerequisites](https://github.com/ch4mpy/spring-addons/blob/master/samples/tutorials/README.md#prerequisites).

## 2. Project
In this section, we'll define a Spring Boot REST API and how we'd like it to be secured.

### 2.1. Initialization
We'll initiate a spring-boot 3.0.2 project with the help of https://start.spring.io/, with the following dependencies:
- Spring Web
- Spring Boot Actuator
- lombok

We'll also need 
- [`springdoc-openapi-starter-webmvc-ui`](https://central.sonatype.com/artifact/org.springdoc/springdoc-openapi-starter-webmvc-ui/2.0.2)
- [`json-path`](https://central.sonatype.com/artifact/com.jayway.jsonpath/json-path/2.7.0)
- [`spring-security-test`](https://central.sonatype.com/artifact/org.springframework.security/spring-security-test/6.0.2) with `test` scope
- [`spring-addons-oauth2-test`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-oauth2-test/6.1.2) with `test` scope

It is worth noting that no Spring Boot starter for security or OAuth2 was added (yet).

### 2.2. REST Controller
We'll use a very simple controller, just accessing basic `Authentication` properties:
```java
@RestController
public class GreetingController {

    @GetMapping("/greet")
    public String getGreeting(Authentication auth) {
        return "Hi %s! You are granted with: %s.".formatted(auth.getName(), auth.getAuthorities());
    }
}
```
This is enough to demo that the username and roles are mapped from different claims depending on the authorization-server which issued the access-token (Keycloak, Auth0 or Cognito).

### 2.3 Security Specifications
This is how we want our REST API to be configured:
- use OAuth2 for requests authorization
- accept identities issued by 3 different OIDC authorization-servers (Keycloak, Auth0 and Cognito)
- enabled CORS (with fine grained configuration per path-matcher)
- state-less session management (no session, user state in access-token only)
- disabled CSRF (safe because there is no session)
- enabled anonymous with public access to a limited list of resources
- non "public" routes require users to be authenticated, fine grained access-control being achieved with method-security (`@PreAuthrorize` and alike)
- 401 (unauthorized) instead 302 (redirecting to login) when a request to a protected resource is made with missing or invalid authorization

### 2.4. Security Properties
There are a few things we want to configure from application properties to bring enough flexibility:
- trusted issuers
- authorities mapping (JSON path to the claim(s) containing roles, prefix and case processing), per issuer
- JSON path of the claim to use as username, per issuer
- fine grained CORS configuration (origin, headers, methods, etc.), per path-matcher
- routes accessible to anonymous

Spring Boot properties won't be enough and we'll have to define our own:
```yaml
origins: http://localhost:4200
keycloak: http://localhost:8442/realms/master
cognito: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
auth0: https://dev-ch4mpy.eu.auth0.com/

com:
  c4-soft:
    springaddons:
      security:
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
          username-claim: $['https://c4-soft.com/spring-addons']['name']
          authorities:
          - path: roles
          - path: permissions
        permit-all: 
        - "/actuator/health/readiness"
        - "/actuator/health/liveness"
        - "/v3/api-docs/**"

management:
  endpoint:
    health:
      probes:
        enabled: true
  endpoints:
    web:
      exposure:
        include: '*'
  health:
    livenessstate:
      enabled: true
    readinessstate:
      enabled: true
```
With such a configuration file, we could easily switch `allowed-origins` and `location` URIs to adapt it to various environments (using environment variables or Spring profiles for instance).

## 3. Configuration with `spring-addons-webmvc-jwt-resource-server`
As we'll see in the next section, we can use Spring Boot starter for resource-servers to configure our REST API. But this is quite verbose and we'd certainly avoid duplicating such a complicated configuration in many micro-services. Instead, we'll use one of the 4 thin open-source wrappers around `spring-boot-starter-oauth2-resource-server` provided by [spring-addons](https://github.com/ch4mpy/spring-addons).

**With above configuration properties and a dependency on [`spring-addons-webmvc-jwt-resource-server`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webmvc-jwt-resource-server/6.0.16), this configuration class is enough:**
```java
@Configuration
@EnableMethodSecurity
public static class WebSecurityConfig {
}
```
Isn't it Bootyful?

The Webflux equivalent with [`spring-addons-webflux-jwt-resource-server`](https://central.sonatype.com/artifact/com.c4-soft.springaddons/spring-addons-webflux-jwt-resource-server/6.0.16) is just as simple (of course, the @Controller would need a slight rework too):
```java
@Configuration
@EnableReactiveMethodSecurity
public static class WebSecurityConfig {
}
```

In the next section, we'll explore what happens under the hood.

## 4. Configuration With `spring-boot-starter-oauth2-resource-server`
The configuration in this section is pretty verbose, but gives a clear idea of what is auto-configured by spring-addons starters.

### 4.1. Preamble
First replace the dependency on `spring-addons-webmvc-jwt-resource-server` with the "official" starter: [`spring-boot-starter-oauth2-resource-server`](https://central.sonatype.com/artifact/org.springframework.boot/spring-boot-starter-oauth2-resource-server/3.0.2).

We'll start building our security configuration from this base:
```java
@EnableWebSecurity
@EnableMethodSecurity
@Configuration
public class WebSecurityConfig {
    interface Jwt2AuthoritiesConverter extends Converter<Jwt, Collection<? extends GrantedAuthority>> {}
    interface Jwt2AuthenticationConverter extends Converter<Jwt, JwtAuthenticationToken> {}
}
```
Aliases, like the two converters we defined here, are useful for the bean factory to distinguish generic instances: without aliases and after type erasure, both converters would have the same `Converter<Object, Object>` interface.

### 4.2. Parsing Configuration Properties
To parse the security properties we defined at [section 2.4.](https://github.com/ch4mpy/spring-addons/blob/master/samples/tutorials/resource-server_with_jwtauthenticationtoken/README.md#24-security-properties), we'll use this `@ConfigurationProperties` class:
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
        private SimpleAuthoritiesMappingProperties[] authorities = { new SimpleAuthoritiesMappingProperties() };
        private String usernameClaim = StandardClaimNames.SUB;
    }

    @Data
    public static class SimpleAuthoritiesMappingProperties {
        private String path = "realm_access.roles";
        private String prefix = "";
        private Case caze = Case.UNCHANGED;
    }

    public static enum Case {
        UNCHANGED, UPPER, LOWER
    }

    public IssuerProperties getIssuerProperties(String iss) throws NotATrustedIssuerException {
        return Stream.of(issuers).filter(issuerProps -> Objects.equals(Optional.ofNullable(issuerProps.getLocation()).map(URI::toString).orElse(null), iss))
                .findAny().orElseThrow(() -> new NotATrustedIssuerException(iss));
    }

    public IssuerProperties getIssuerProperties(Object iss) throws NotATrustedIssuerException {
        if (iss == null && issuers.length == 1) {
            return issuers[0];
        }
        return getIssuerProperties(Optional.ofNullable(iss).map(Object::toString).orElse(null));
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public static final class NotATrustedIssuerException extends RuntimeException {
        private static final long serialVersionUID = 3122111462329395017L;

        public NotATrustedIssuerException(String iss) {
            super("%s is not configured as trusted issuer".formatted(iss));
        }
    }
}
```

### 4.3. Authorities Converter
As a reminder, the `scope` of a token defines what a resource-owner allowed an OAuth2 client to do on his behalf, when "roles" are a way to represent what a resource-owner himself is allowed to do on resource-servers.

RBAC is a very common pattern for access-control, but neither OAuth2 nor OpenID define a standard representation for "roles". Each vendor implements it with its own private-claim(s).

Spring Security default authorities mapper, which maps from the `scope` claim, adding the `SCOPE_` prefix, won't satisfy to our needs (unless we twisted the usage of the `scope` claim on the authorization-server to contain user roles, off course).

So, we need a converter to extract spring-security `GrantedAuthority` collection from claims of our choice. In a first iteration, we'll use Keycloak `realm_access.roles` as source for authorities:
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
@Component
@RequiredArgsConstructor
public class ConfigurableClaimSet2AuthoritiesConverter implements Jwt2AuthoritiesConverter {
    private final SpringAddonsSecurityProperties properties;

    @Override
    public Collection<? extends GrantedAuthority> convert(Map<String, Object> source) {
        final var authoritiesMappingProperties = getAuthoritiesMappingProperties(source);
        // @formatter:off
        return Stream.of(authoritiesMappingProperties)
                .flatMap(authoritiesMappingProps -> getAuthorities(source, authoritiesMappingProps))
                .map(r -> (GrantedAuthority) new SimpleGrantedAuthority(r)).toList();
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
    
    private SimpleAuthoritiesMappingProperties[] getAuthoritiesMappingProperties(Map<String, Object> claimSet) {
        final var iss = Optional.ofNullable(claimSet.get(JwtClaimNames.ISS)).orElse(null);
        return properties.getIssuerProperties(iss).getAuthorities();
    }
    
    private static Stream<String> getAuthorities(Map<String, Object> claims, SimpleAuthoritiesMappingProperties props) {
        // @formatter:off
        return getRoles(claims, props.getPath())
                .map(r -> processCase(r, props.getCaze()))
                .map(r -> String.format("%s%s", props.getPrefix(), r));
        // @formatter:on
    }
    
    @SuppressWarnings({ "rawtypes", "unchecked" })
    private static Stream<String> getRoles(Map<String, Object> claims, String path) {
        try {
            final var res = JsonPath.read(claims, path);
            if (res instanceof String r) {
                return Stream.of(r);
            }
            if (res instanceof List l) {
                if (l.size() == 0) {
                    return Stream.empty();
                }
                if (l.get(0) instanceof String) {
                    return l.stream();
                }
                if (l.get(0) instanceof List) {
                    return l.stream().flatMap(o -> ((List) o).stream());
                }
            }
            return Stream.empty();
        } catch (PathNotFoundException e) {
            return Stream.empty();
        }
    }
}
```

**Cool, we can now map authorities from any OAuth2 access-token, issued by any authorization-server, by just editing a configuration property!**

### 4.4. Authentication Converter & `AuthenticationManagerResolver`
As we already defined a powerful authorities converter, defining an authentication converter is just a matter of calling it and retrieving the username, following the configured JSON path:
```java
@Bean
Jwt2AuthenticationConverter authenticationConverter(
        Converter<Jwt, Collection<? extends GrantedAuthority>> authoritiesConverter,
        SpringAddonsSecurityProperties addonsProperties) {
    return jwt -> new JwtAuthenticationToken(
            jwt,
            authoritiesConverter.convert(jwt),
            JsonPath.read(jwt.getClaims(), addonsProperties.getIssuerProperties(jwt.getIssuer()).getUsernameClaim()));
}
```

This would be just enough if we accepted identities from a single issuer, but as we are in a multi-tenant scenario, we should override the `AuthenticationManagerResolver` too, so that the `JwtDecoder`, as well as authorities and authentication converters, match the access-token issuer:
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

### 4.5. CORS Configuration
Spring's `CorsConfigurationSource` allows us to fine tune `CorsConfiguration` for as many path-matchers as we like. Let's parse our properties to create such a CORS configuration source:
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
**Great! We can can now easily adapt CORS configuration when switching environments.** For instance, allowed origin could be https://localhost:4200, https://dev.myapp.pf or https://www.myapp.pf depending on where we deploy.

### 4.6. Security Filter-Chain
Now that we have all of the required beans and utility methods at hand, let's assemble the security filter-chain
```java
@Bean
SecurityFilterChain filterChain(
        HttpSecurity http,
        ServerProperties serverProperties,
        SpringAddonsSecurityProperties addonsProperties,
        AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) throws Exception {

    // Configure the app as resource-server with an authentication manager resolver capable of handling multi-tenancy
    http.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(authenticationManagerResolver));

    // Enable anonymous
    http.anonymous();

    // Enable and configure CORS (or disable it if there's no CORS properties at all)
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
    http.authorizeHttpRequests()
        .requestMatchers(addonsProperties.getPermitAll()).permitAll()
        .anyRequest().authenticated();

    return http.build();
}
```

## 5. Conclusion
This tutorial explained how to build a very flexible security configuration for a servlet resource-server with JWT decoder. To configure a webflux resource-server or use access-token introspection instead of JWT decoding, or using custom `Authentication` implementations, please refer to [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples).

You might also explore source code to have a look at how to mock identities in unit and integration tests and assert  access-control is behaving as expected. All samples and tutorials include detailed access-control tests.
