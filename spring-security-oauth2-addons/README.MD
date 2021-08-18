# spring-security OAuth2 addons

1. [Abstract](#abstract)<br/>
2. [Scopes & Authorities](#scopes-authorities)<br/>
3. [Sample usage](#sample)<br/>

``` xml
    <dependencies>
        <dependency>
            <groupId>com.c4-soft.springaddons</groupId>
            <artifactId>spring-security-oauth2-addons</artifactId>
            <version>${com.c4-soft.springaddons.version}</version>
        </dependency>
    </dependencies>
```

<a name="abstract"/>

## What's in there ?

What I propose here are tools to extend spring-security for OAuth2.
It could grow, but is currently limited to a portable `Authentication` implementation for OpenID.

`OidcIdAuthenticationToken` is intended to be used with any OpenID authorization server (Keycoak, Auth0, MS Identity Server, ...).
Here are few key features when compared to `JwtAuthenticationToken` or `BearerTokenAuthentication`:
 * no mess up between scopes and authorities
 * principal and credentials are typed with something more actionable than `Object`
 * structure as close as possible to the standard

<a name="scopes-authorities"/>

## Scopes and authorites
Why don't I use authentication converters provided by spring-boot?

Mostly because:
- I prefer `OidcIdAuthenticationToken` over `JwtAuthenticationToken`, `BearerTokenAuthentication` (see above) and `KeycloakAuthenticationToken` (too vendor specific)
- I want resource-server to retieve authorities, depending on configuration, from one of the following
  * JWT private claims (like Keycloak `realm_access.roles` and `resource_access.${clientId}.roles`)
  * relational database using a JPA or R2DBC repository (query athorities by end-user `subject`)
   
### Authorities
Authorities define what an end-user is allowed to do with the resource-server. There is no spec about authorities in OpenID nor OAuth2.
It is possible to embed authorities in JWT tokens using private claims, but it's also possible for the resource server to retrieve authorities from elswhere like a database.

### Scopes
As explained in introduction, IMO scopes should be a **mask** on end-user permissions. This mask allows end-user to control what he allows clients to do in his name with resources he (the user) owns.

Lets illustrate how different the relation between scopes and authorities can be with two extreme samples:
 * social-network resource-server with many "untrusted" clients: 
   you need almost a scope per authority to define precisely what the user allows each client can access (age, gender, phone, friends, etc.)
 * resource server with a single trusted client (back-end for mobile or Angular application for instance): no scope at all required. 
   If user authenticates with the client, the client should be able to do whatever the user is alowed to.

### Token-claims embedded authorities

If authorization-server puts already "scoped" authorities in a private claim,
it is then very simple for resource-servers to build authentications as both name and authorities are contained in the token claims but:
 * tokens can come fat when number of clients and resource-servers grows
 * induces high coupling on authorities definitions between authorization and resource servers: 
   updating authorities definition for a service could require modifying the authorization server (at least its database)
   which can be an issue when maintained by another team

### Authorities retrieved from an external source with token subject

Authorization-server acts in 3 steps
1. end-user ID is extracted from the token (`subject` claim is a natural candidate)
2. retrieves authorities fetching an external source (like a DB)
3. restrict authorities according to token scopes (if relevant)

Of course, this requires the resource-server to have more logic to retrieve those authorities from an external source (delegate to a `Repository`?)
and filter it according to scopes (if necessary as some resource-servers with single clients are frequently happy with all-or-nothing strategy) => consumes more resources and takes longer to process

<a name="sample"/>

## Sample usage

Both samples are designed for a Keycloak authorisation server embedding authorities (user roles) in `resource_access.${clientId}.roles` claim.

If your authorisation server puts authorities in private claim, adapting the samples should be straight forward.

If you opted for an external authorities datasource, you might prefer to explicitely define an `authoritiesConverter` bean in which you'll inject an authorities repository.

### Servlet (webmvc)

``` java
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${com.c4-soft.security.oauth2.client-id}")
    String clientId;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(authenticationConverter());

        // more HttpSecurity configuration
    }

    SynchronizedJwt2OidcIdAuthenticationConverter authenticationConverter() {
        return new SynchronizedJwt2OidcIdAuthenticationConverter(authoritiesConverter());
    }

    SynchronizedJwt2GrantedAuthoritiesConverter authoritiesConverter() {
        return (Jwt jwt) -> {
            final var roles =
                Optional
                    .ofNullable((JSONObject) jwt.getClaims().get("resource_access"))
                    .flatMap(resourceAccess -> Optional.ofNullable((JSONObject) resourceAccess.get(clientId)))
                    .flatMap(clientResourceAccess -> Optional.ofNullable((JSONArray) clientResourceAccess.get("roles")))
                    .orElse(new JSONArray());

                return roles.stream().map(Object::toString).map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
        }
    }
}
```

### Reactive (webflux)

``` java
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class WebSecurityConfig {

    @Value("${com.c4-soft.security.oauth2.client-id}")
    String clientId;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {

        http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(authenticationConverter());

        // more ServerHttpSecurity configuration

        return http.build();
    }

    ReactiveJwt2OidcIdAuthenticationConverter authenticationConverter() {
        return new ReactiveJwt2OidcIdAuthenticationConverter(authoritiesConverter());
    }

    ReactiveJwt2GrantedAuthoritiesConverter authoritiesConverter() {
        return (Jwt jwt) -> {
            final var roles =
                Optional
                    .ofNullable((JSONObject) jwt.getClaims().get("resource_access"))
                    .flatMap(resourceAccess -> Optional.ofNullable((JSONObject) resourceAccess.get(clientId)))
                    .flatMap(clientResourceAccess -> Optional.ofNullable((JSONArray) clientResourceAccess.get("roles")))
                    .orElse(new JSONArray());

                return Flux.fromStream(roles.stream().map(Object::toString).map(SimpleGrantedAuthority::new));
        }
    }
}
```
