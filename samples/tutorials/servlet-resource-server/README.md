# Configure a Servlet OAuth2 Resource Server (REST API)
In this tutorial, we'll configure a servlet (WebMVC) Spring Boot 3 application as an OAuth2 resource server with authorities mapping to enable RBAC using roles defined on OIDC Providers.

We'll also see how to accept access tokens issued by several, potentially heterogeneous, OIDC Providers (or Keycloak realms).

## 1. Project Initialization
We start after [prerequisites](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#2-prerequisites), and consider that we have a minimum of 1 OIDC Provider configured (2 would be better) and users with and without `NICE` role declared on each OP.
As usual, we'll start with http://start.spring.io/ adding the following dependencies:
- Spring Web
- OAuth2 Resource Server
- lombok

## 2. REST Controller
We'll use a very simple controller, just accessing basic `Authentication` properties:
```java
@RestController
public class GreetingController {

	@GetMapping("/greet")
	public MessageDto getGreeting(Authentication auth) {
		return new MessageDto("Hi %s! You are granted with: %s.".formatted(auth.getName(), auth.getAuthorities()));
	}

	static record MessageDto(String body) {
	}
}
```
This is enough to demo that the username and roles are mapped from different claims depending on the authorization-server which issued the access token (Keycloak, Auth0 or Cognito).

## 3 Security Configuration
This is how we want our REST API to be configured:
- use OAuth2 for requests authorization
- accept identities issued by 3 different OIDC authorization-servers (Keycloak, Auth0 and Cognito)
- enabled CORS (with configurable allowed origins)
- state-less session management (no session, user state in access token only)
- disabled CSRF (safe because there is no session)
- public access to a limited list of resources
- non "public" routes require users to be authenticated, fine grained access-control being achieved with method-security (`@PreAuthrorize` and alike)
- 401 (unauthorized) instead 302 (redirecting to login) when a request to a protected resource is made with missing or invalid authorization

## 3.1. Security Properties
Let's replace our `application.properties` file with an `application.yml` having the following content:
```yaml
scheme: http
origins: http://localhost:4200,https://localhost:4200
permit-all: /public/**
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
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: ${keycloak-issuer}

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

---
spring:
  config:
    activate:
      on-profile: auth0
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: ${auth0-issuer}

---
spring:
  config:
    activate:
      on-profile: cognito
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: ${cognito-issuer}
```
There are a few things worth noting here:
- `spring.security.oauth2.resourceserver.jwt.issuer-uri` is single valued. This means that Spring Boot accepts OAuth2 identities issued only by a single OIDC Provider at a time. We use profiles to switch our resource server from one OP to another. This requires a restart, but we'll see how to configure spring-security to accept identities from several OIDC Providers in a single resource server instance.
- there are values (issuer URIs) which need an edit with what was obtained when accomplishing [prerequisites](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#2-prerequisites).

### 3.2. Security Filter-Chain
As development and production environments will likely allow different origins, we need a CORS configuration function taking allowed-origins as parameter.

Also, when a request to a protected resource is made with a missing or invalid authorization the HTTP status should be 401 (`Unauthorized`) but, by default, Spring returns 302 (redirect to login, which makes no sense on a resource server). To change that, we'll have to write an access denied handler.

Let's put our security configuration together and provide a security filter-chain bean complying with all our specifications:
```java
@EnableWebSecurity
@EnableMethodSecurity
@Configuration
public class WebSecurityConfig {

    @Bean
    SecurityFilterChain
            filterChain(HttpSecurity http, ServerProperties serverProperties, @Value("origins") String[] origins, @Value("permit-all") String[] permitAll)
                    throws Exception {

        http.oauth2ResourceServer(resourceServer -> resourceServer.jwt());

        // State-less session (state in access token only)
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

		// @formatter:off
        http.authorizeHttpRequests()
            .requestMatchers(permitAll).permitAll()
            .anyRequest().authenticated();
        // @formatter:on

		return http.build();
    }

    private UrlBasedCorsConfigurationSource corsConfigurationSource(String[] origins) {
        final var configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(origins));
        configuration.setAllowedMethods(List.of("*"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setExposedHeaders(List.of("*"));
    
        final var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

### 3.3. Authorities Mapping
As a reminder, the `scope` of a token defines what a resource-owner allowed an OAuth2 client to do on his behalf, when "roles" are a way to represent what a resource-owner himself is allowed to do on s.

RBAC is a very common pattern for access-control, but neither OAuth2 nor OpenID define a standard representation for "roles". Each vendor implements it with its own private-claim(s).

Spring Security default authorities mapper, which maps from the `scope` claim, adding the `SCOPE_` prefix, won't satisfy to our needs (unless we twisted the usage of the `scope` claim on the authorization-server to contain user roles, off course).

We'll implement a mapping of Spring Security authorities from OpenID private claims with the following specifications:
- possibly use several claims as source, all of those claims being a string array or a single string of comma separated values (Keycloak for instance can provide with roles in `realm_access.roles` and `resource_access.{client-id}.roles`)
- configure case processing and prefix independently for each claim (for instance use `SCOPE_` prefix for scopes in `scp` claim and `ROLE_` prefix for roles in `realm_access.roles` one)
- provide with a different configuration for each provider (Keycloak, Auth0 and Cognito all use different private claims for user roles)

#### 3.3.1. Dependencies
To ease roles claims parsing, we'll use [json-path](https://central.sonatype.com/artifact/com.jayway.jsonpath/json-path/2.8.0). Let's add it to our dependencies:
```xml
<dependency>
    <groupId>com.jayway.jsonpath</groupId>
    <artifactId>json-path</artifactId>
</dependency>
```

#### 3.3.2. Application Properties
Then, we need some additional configuration properties to provide with the flexibility to change, for each issuer the claims containing the user name and roles
```java
@Data
@Configuration
@ConfigurationProperties(prefix = "spring-addons")
public class SpringAddonsProperties {
    private IssuerProperties[] issuers = {};

    @Data
    static class IssuerProperties {
        private URL uri;
        private ClaimMappingProperties[] claims;
        private String usernameJsonPath = JwtClaimNames.SUB;

        @Data
        static class ClaimMappingProperties {
            private String jsonPath;
            private CaseProcessing caseProcessing = CaseProcessing.UNCHANGED;
            private String prefix = "";

            static enum CaseProcessing {
                UNCHANGED, TO_LOWER, TO_UPPER
            }
        }
    }

    public IssuerProperties get(URL issuerUri) throws MisconfigurationException {
        final var issuerProperties = Stream.of(issuers).filter(iss -> issuerUri.equals(iss.getUri())).toList();
        if (issuerProperties.size() == 0) {
            throw new MisconfigurationException("Missing authorities mapping properties for %s".formatted(issuerUri.toString()));
        }
        if (issuerProperties.size() > 1) {
            throw new MisconfigurationException("Too many authorities mapping properties for %s".formatted(issuerUri.toString()));
        }
        return issuerProperties.get(0);
    }

    static class MisconfigurationException extends RuntimeException {
        private static final long serialVersionUID = 5887967904749547431L;

        public MisconfigurationException(String msg) {
            super(msg);
        }
    }
}
```
We'll also need the yaml properties matching this configuration:
```yaml
spring-addons:
  issuers:
  - uri: ${keycloak-issuer}
    username-json-path: $.preferred_username
    claims:
    - jsonPath: $.realm_access.roles
    - jsonPath: $.resource_access.*.roles
  - uri: ${cognito-issuer}
    claims:
    - jsonPath: $.cognito:groups
  - uri: ${auth0-issuer}
    claims:
    - jsonPath: $.roles
    - jsonPath: $.groups
    - jsonPath: $.permissions
```

#### 3.3.3. Authorities and Authentication Converters
We can now write a converter bean building Spring authorities from JWT claims, as specified in the configuration above:
```java
@RequiredArgsConstructor
static class JwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<? extends GrantedAuthority>> {
    private final SpringAddonsProperties.IssuerProperties properties;

    @Override
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public Collection<? extends GrantedAuthority> convert(Jwt jwt) {
        return Stream.of(properties.claims).flatMap(claimProperties -> {
            Object claim;
            try {
                claim = JsonPath.read(jwt.getClaims(), claimProperties.jsonPath);
            } catch (PathNotFoundException e) {
                claim = null;
            }
            if (claim == null) {
                return Stream.empty();
            }
            if (claim instanceof String claimStr) {
                return Stream.of(claimStr.split(","));
            }
            if (claim instanceof String[] claimArr) {
                return Stream.of(claimArr);
            }
            if (Collection.class.isAssignableFrom(claim.getClass())) {
                final var iter = ((Collection) claim).iterator();
                if (!iter.hasNext()) {
                    return Stream.empty();
                }
                final var firstItem = iter.next();
                if (firstItem instanceof String) {
                    return (Stream<String>) ((Collection) claim).stream();
                }
                if (Collection.class.isAssignableFrom(firstItem.getClass())) {
                    return (Stream<String>) ((Collection) claim).stream().flatMap(colItem -> ((Collection) colItem).stream()).map(String.class::cast);
                }
            }
            return Stream.empty();
        }).map(SimpleGrantedAuthority::new).map(GrantedAuthority.class::cast).toList();
    }
}
```
This authorities converter will be instantiated and used by such an authentication converter:
```java
@Component
@RequiredArgsConstructor
static class SpringAddonsJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    private final SpringAddonsProperties springAddonsProperties;

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        final var issuerProperties = springAddonsProperties.get(jwt.getIssuer());
        final var authorities = new JwtGrantedAuthoritiesConverter(issuerProperties).convert(jwt);
        final String username = JsonPath.read(jwt.getClaims(), issuerProperties.getUsernameJsonPath());
        return new JwtAuthenticationToken(jwt, authorities, username);
    }
}
```

#### 3.3.4. Security Configuration Update
The last missing configuration piece is an update of the security filter-chain: inject our authentication converter in th resource server configuration:
```java
@Bean
SecurityFilterChain filterChain(
        HttpSecurity http,
        ServerProperties serverProperties,
        @Value("origins") String[] origins,
        @Value("permit-all") String[] permitAll,
        SpringAddonsProperties springAddonsProperties,
        SpringAddonsJwtAuthenticationConverter authenticationConverter)
        throws Exception {

    http.oauth2ResourceServer(resourceServer -> resourceServer.jwt(jwtConf -> jwtConf.jwtAuthenticationConverter(authenticationConverter)));

...

return http.build();
}
```
**Cool, we can now map authorities from any JWT access token, issued by any OIDC Provider, by just editing a configuration property!**

#### 3.3.5. Restricted End-Point
To demo **R**ole **B**ased **A**ccess **C**ontrol, we'll edit our `@RestController` to add a new end-point only accessible to users granted with the `NICE` role:
```java
@GetMapping("/restricted")
@PreAuthorize("hasAuthority('NICE')")
public MessageDto getRestricted() {
    return new MessageDto("You are so nice!");
}
```

### 4. Multi-Tenancy
So far, our resource server is able to accept identities issued by a any OIDC Provider, but only one per resource server instance. This is frequently enough, but not always.

For instance, when working with Keycloak, we can consider all realms as distinct OPs. We'll have to provide some additional configuration for a single resource server instance to accept requests from users identified on different realms.

Let's first remove the `spring.security.oauth2.resourceserver.jwt.issuer-uri` which is not adapted to our use-case. We'll iterate over the `spring-addons.issuers` instead. We can remove the `auth0` and `cognito` profiles too.

Next, we'll define an `AuthenticationManagerResolver`:
```java
@Bean
AuthenticationManagerResolver<HttpServletRequest>
		authenticationManagerResolver(SpringAddonsProperties addonsProperties, SpringAddonsJwtAuthenticationConverter authenticationConverter) {
	final Map<String, AuthenticationManager> authenticationProviders =
			Stream.of(addonsProperties.getIssuers()).map(SpringAddonsProperties.IssuerProperties::getUri).map(URL::toString)
					.collect(Collectors.toMap(issuer -> issuer, issuer -> authenticationProvider(issuer, authenticationConverter)::authenticate));
	return new JwtIssuerAuthenticationManagerResolver((AuthenticationManagerResolver<String>) authenticationProviders::get);
}

JwtAuthenticationProvider authenticationProvider(String issuer, SpringAddonsJwtAuthenticationConverter authenticationConverter) {
	JwtDecoder decoder = JwtDecoders.fromIssuerLocation(issuer);
	var provider = new JwtAuthenticationProvider(decoder);
	provider.setJwtAuthenticationConverter(authenticationConverter);
	return provider;
}
```

Last, when configuring the resource server within the security filter-chain, we'll replace the authentication converter configuration with our new authentication manager resolver:
```java
@Bean
SecurityFilterChain filterChain(
		HttpSecurity http,
		ServerProperties serverProperties,
		@Value("origins") String[] origins,
		@Value("permit-all") String[] permitAll,
		AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver)
		throws Exception {

    // Configure the app as  with an authentication manager resolver capable of handling multi-tenancy
	http.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(authenticationManagerResolver));
    ...
    return http.build();
}
```

## 5. Conclusion
In this tutorial, we configured a servlet (WebMVC) Spring Boot 3 application as an OAuth2 resource server with authorities mapping to enable RBAC using roles defined in as many OIDC Providers (or Keycloak realms) as we need, no matter if they send user roles in the same claim(s).

But wait, what we did here is pretty verbose and we'll need it in almost any OAuth2 resource server we write. Do we really have to write all that again and again? Not really: this repo provides with a [`spring-addons-webmvc-jwt-resource-server`](https://github.com/ch4mpy/spring-addons/tree/master/webmvc/spring-addons-webmvc-jwt-resource-server) Spring Boot starter just for that, with a [sample usage there](https://github.com/ch4mpy/spring-addons/tree/master/samples/webmvc-jwt-default). And if for whatever reason you don't want to use that one, you can still write [your own starter](https://docs.spring.io/spring-boot/docs/current/reference/html/features.html#features.developing-auto-configuration) to wrap the configuration we wrote here.

You might also explore source code to have a look at how to mock identities in unit and integration tests and assert access-control is behaving as expected. All samples and tutorials include detailed access-control tests.
