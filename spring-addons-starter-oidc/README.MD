# spring-addons-starter-oidc

This project is a Spring Boot starter to use in addition to `spring-boot-starter-oauth2-client` or `spring-boot-starter-oauth2-resource-server` to further **ease OAuth2 configuration with any OpenID Provider, and potentially several heterogeneous ones at a time**.

```xml
    <properties>
        <springaddons.version>7.9.0</springaddons.version>
    </properties>
    
    <dependencies>
        <!-- the following is a complement (not a replacement) to 
        spring-boot-starter-oauth2-resource-server or spring-boot-starter-oauth2-client (or both) -->
        <dependency>
            <groupId>com.c4-soft.springaddons</groupId>
            <artifactId>spring-addons-starter-oidc</artifactId>
            <version>${springaddons.version}</version>
        </dependency>
        <dependency>
            <groupId>com.c4-soft.springaddons</groupId>
            <artifactId>spring-addons-starter-oidc-test</artifactId>
            <version>${springaddons.version}</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
```

Jump to:
- [0. Risks Of Using These Libs And Mitigations](#drawbacks)
- [1. Features](#features)
  * [1.1. OAuth2 Resource Servers](#features-resource-server)
    - [1.1.1. Resource Server `Security(Web)FilterChain`](#1-1-1)
    - [1.1.2. Authorities Converter](#1-1-2)
    - [1.1.3. Authentication Converter](#1-1-3)
    - [1.1.4. Multi-Tenancy](#1-1-4)
    - [1.1.5. Access Control](#1-1-5)
    - [1.1.6. CORS Configuration](#1-1-6)
    - [1.1.7. Post-Process the Resource Server Filer-Chain](#1-1-7)
  * [1.2. OAuth2 Clients with `oauth2Login`](#features-client)
    - [1.2.1. Client `Security(Web)FilterChain`](#1-2-1)
    - [1.2.2. Setting a Base URI for the Client](#1-2-2)
    - [1.2.3. Authorization Code](#1-2-3)
    - [1.2.4. RP-Initiated Logout](#1-2-4)
    - [1.2.5. Back-Channel Logout](#1-2-5)
    - [1.2.6. Authorities Converter](#1-2-6)
    - [1.2.7. CSRF protection](#1-2-7)
    - [1.2.8. Multi-Tenancy](#1-2-8)
    - [1.2.9. Access Control](#1-2-9)
    - [1.2.10. Post-Process the Client Filer-Chain](#1-2-10)
    - [1.2.11. Add Parameters to Token Requests](#1-2-11)
- [2. Frequently Asked Questions](#faq)
  * [What exactly is auto-configured?](#2-1)
  * [Are all those beans defined by `spring-addons-starter-oidc` added to my application context?](#2-2)
  * [Why all this fuss around authorities mapping? Can't I just keep the default using scopes?](#2-3)
  * [How to configure a resource server to accept tokens issued for Keycloak *realms* created at runtime?](#2-4)
  * [How to provide the `audience` parameter required by Auth0 for user login?](#2-5)
  * [How to provide the `audience` parameter reuqired by Auth0 for client-credentials?](#2-6)
  * [Can a frontend override post-login URL?](#2-7)
  * [Can a frontend override post RP-Initiated Logout URL?](#2-8)
  * [Can a frontend override the response status for OAuth2 redirections?](#2-9)
  * [Is `iss` configuration property mandatory?](#2-10)
  * [Why can't I get things working easily with Microsoft authorization servers?](#2-11)
- [3. Usage](#usage)
  * [3.1. Resource Server](#3-1)
  * [3.2. Client](#3-2)
  * [3.3. Client and Resource Server](#3-3)

## 0. <a name="drawbacks"/>Risks Of Using These Libs And Mitigations
Neither the owner of this repo nor any of the contributors are part of Spring Security team. At best, some are occasional contributors to the "official" framework.

However, unless you have a deep knowledge of Spring Security for OAuth2, using `spring-addons-starter-oidc` might actually be safer than experimenting with the conf by yourself. And the more popularity this repo gets, the safer it is: more people detect potential issues, more people can keep it alive if its initiator disappears and, if some features where to become popular enough, Spring team could consider pulling it in the official framework.

Also, all you have to do to opt-out `spring-addons-starter-oidc` at any point in time is writing Spring Security Configuration by yourself. Refer to tutorials if you need some guidance to do that, the following are written without `spring-addons-starter-oidc` (just `spring-boot-starter-oauth2-client` or `spring-boot-starter-oauth2-resource-server`):
- [reactive-client](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/reactive-client)
- [reactive-resource-server](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/reactive-resource-server)
- [servlet-client](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/servlet-client)
- [servlet-resource-server](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/servlet-resource-server)

What are the identified risks of using the resources from such a repo and how can you protect against it?
- *what if the updates to latest dependencies stop and no PR are merged anymore?* You can fork this repo and start a new branch from the last tag you like
- *what if the library takes a direction I don't like?* Same as for a stale repo
- *what if the owner deletes this repo or makes it private?* The source code for each release is published to maven-central. You can get the source [there](https://repo1.maven.org/maven2/com/c4-soft/springaddons/) or from any of the forks on GitHub (about 50 in August 2023).
- *what is the risk of vulnerabilities introduced by the code in these libs?* This depends on the lib:
  * libs to be used during tests (`spring-addons-oauth2-test` and `spring-addons-starter-oidc-test`) should be imported with `test` scope => it should not be present at runtime => no risk in production
  * `spring-addons-starter-oidc` does some auto-configuration for you: it defines Spring beans involved in your application security. So yes, if a default is miss-configured in this lib, it can have an impact on your app. You should however consider that:
    - an increasing number of user inspect it and open issues or PRs when detecting a problem (the community is probably much bigger than your team working at detecting Spring Security configuration issues in your own projects)
    - having code centralised at one place and reused at many places reduces the risk of a careless mistake in one of your app

## 1. <a name="features"/>Features
### 1.1. <a name="features-resource-server"/>OAuth2 Resource Servers
As a reminder, requests to an OAuth2 resource server are authorized with access tokens, which are validated either with introspection or JWT decoders.

Resource servers only care if tokens are valid and if it should grant access to resources based on the claims associated to it. Resource servers are not concerned by how token are obtained. As a consequence, login and logout are not relevant in resource server configuration.

#### 1.1.1. <a name="1-1-1"/>Resource Server `Security(Web)FilterChain`
If `spring-boot-starter-oauth2-resource-server` is on the classpath and unless `com.c4-soft.springaddons.oidc.resourceserver.enabled=false`, a `Security(Web)FilterChain` is created with the following default configuration:
- `@Order(Ordered.LOWEST_PRECEDENCE)` and no security matcher (acts as default, processing all requests which weren't intercepted by any other `Security(Web)FilterChain` with higher precedence)
- stateless (no session and CSRF protection disabled)
- respond with 401 to unauthorized requests
- access token introspection if `spring.security.oauth2.resourceserver.opaquetoken.introspection-uri` is set and JWT decoder otherwise
- CORS disabled (unless some `cors` properties are provided)
- anonymous access allowed to pre-flight requests as well as all requests with a path matching an entry in `permit-all`; all others requests requiring a valid authentication

#### 1.1.2. <a name="1-1-2"/>Authorities Converter
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

#### 1.1.3. <a name="1-1-3"/>Authentication Converter
Spring Security `Authentication` is more than just a container for *authorities*: it also holds user unique identifier (`name`) and, in the case of a resource server, the access token claims. 

By default, `spring-addons-starter-oidc` uses a `(Reactive)JwtAbstractAuthenticationTokenConverter` or `(Reactive)OpaqueTokenAuthenticationConverter` implementation delegating authorities conversion to a `@Bean` in the context (see previous section). The default output are as usual:
- `JwtAuthenticationToken` when a JWT decoder is used
- `BearerTokenAuthentication` with introspection.

By exposing a custom authentication converter bean, you can use your own `Authentication` implementation. Here is a sample for a servlet with JWT decoder(s):
```java
@Bean
JwtAbstractAuthenticationTokenConverter authenticationConverter(
        Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
        OpenidProviderPropertiesResolver opPropertiesResolver) {
    return jwt -> {
        final var opProperties = opPropertiesResolver.resolve(jwt.getClaims());
        final var claims = new OpenidClaimSet(jwt.getClaims(), opProperties.getUsernameClaim());
        final var authorities = authoritiesConverter.convert(jwt.getClaims());
        return new OAuthentication<>(claims, authorities, jwt.getTokenValue());
    };
}
```

#### 1.1.4. <a name="1-1-4"/>Multi-Tenancy
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

#### 1.1.5. <a name="1-1-5"/>Access Control
The default access rule is set to `isAuthenticated()` with two exceptions:
- routes matching the path-matchers listed in `permit-all` property for which anonymous requests are allowed
- pre-flight requests, unless disabled in `cors` properties (`OPTIONS` requests to routes matching the path-matchers listed in CORS properties).

The most convenient way to define fine-grained access control is probably to `@Enable(Reactive)MethodSecurity` and to decorate `@RestController` methods with `@PreAuthorize`.

For those preferring access control in configuration (or when you don't write the endpoint yourself), you can expose a `@Bean` of type `ResourceServerExpressionInterceptUrlRegistryPostProcessor` or `ResourceServerAuthorizeExchangeSpecPostProcessor`.

#### 1.1.6. <a name="1-1-6"/>CORS Configuration
Starting from version `7.8.7`, the CORS configuration is made using a global filter, behavior of which is control with application properties:
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

#### 1.1.7. <a name="1-1-7"/>Post-Process the Resource Server Filer-Chain
By exposing a `ResourceServer(Server)HttpSecurityPostProcessor` bean, you get complete control of the `(Server)HttpSecurity` configured in the `resourceServerSecurityFilterChain` just before it is built. This allows to change about anything that was pre-configured.

### 1.2. <a name="features-client"/>OAuth2 Clients with `oauth2Login`
OAuth2 clients are applications fetching tokens from an authorization server to later authorize queries to a resource server. Spring Security `oauth2Login` configures the authorization code and the refresh token flows.

When `oauth2Login` is configured on a filter-chain, this filter-chain has to be statefull (tokens are stored in sessions) and protected against CSRF.

Note that `spring-addons-starter-oidc` creates default `(Reactive)OAuth2AuthorizedClientProvider` and `(Reactive)OAuth2AuthorizedClientManager` for all OAuth2 clients (even when the `clientSecurityFilterChain` is disabled) to handle additional parameters on token request. As usual, you can opt-out this default beans by exposing your own.

#### 1.2.1. <a name="1-2-1"/>Client `Security(Web)FilterChain`
A client filter-chain is created if (and only if) all the following conditions are met:
- `spring-boot-starter-oauth2-client` is on the classpath
- `spring.security.oauth2.client.registration` contains at least one entry with `authorization-grant-type=authorization_code`
- `com.c4-soft.springaddons.oidc.client.security-matchers` is not empty

This filter-chain is configured with the following defaults:
- `@Order(Ordered.LOWEST_PRECEDENCE + 1)`
- the security-matcher in the conf is applied
- stateful (session and CSRF protection enabled)
- oauth2Login
- RP-Initiated Logout
- CORS disabled (unless some `cors` properties are provided)
- anonymous access allowed to pre-flight requests as well as all requests with a path matching an entry in `permit-all`; all others requests requiring a valid authentication

#### 1.2.2. <a name="1-2-2"/>Setting a Base URI for the Client
Authorization-code flow and RP-Initiated Logout involve some redirection to the authorization server and then back to the client.

Spring Security generates this redirection URIs, but sometimes, it is convenient to have it point to another host than the client itself: a gateway, reverse-proxy, ingress or whatever. `com.c4-soft.springaddons.oidc.client.client-uri` serves that purpose.

#### 1.2.3. <a name="1-2-3"/>Authorization Code
It is possible to force PKCE usage even for confidential clients by setting `com.c4-soft.springaddons.oidc.client.pkce-forced=true` (By default, Spring enables PKCE only for "public" clients).

Other features are of interest mainly in the case of remote frontends connected to a Spring backend with `oauth2Login` (OAuth2 BFF).

Customization can be achieved by exposing a variety of beans:
- `PreAuthorizationCode(Server)RedirectStrategy`: the default is `SpringAddonsPreAuthorizationCode(Server)RedirectStrategy` which allows to change the status of the redirection to the authorization server when initiating an authorization code flow (`com.c4-soft.springaddons.oidc.client.oauth2-redirections.pre-authorization-code` property or `X-RESPONSE-STATUS` header). This can be of use for frontends wishing to switch the HTTP client on the fly (like a mobile app using a programmatic client with a session on the Spring client and a web-view or system browser with another session for login on the authorization server)
- `(Server)OAuth2AuthorizationRequestResolver`: the default is `SpringAddons(Server)OAuth2AuthorizationRequestResolver` which:
  * forces PKCE usage if the `pkce-forced` is set to `true`
  * switches the client base URI (if requested)
  * saves in session the post-login success and failure URI (provided as `X-POST-LOGIN-SUCCESS-URI` & `X-POST-LOGIN-FAILURE-URI` headers or `post_login_success_uri` & `post_login_failure_uri` request params)
  * adds optional requests params defined under `com.c4-soft.springaddons.oidc.client.authorization-request-params.{registrationId}`. Auth0 for instance, requires an `audience` parameter to be added to authorization request (see FAQ for a sample).
- `(Server)AuthenticationSuccessHandler`: the default restores the post-login success URI saved in session and applies the `com.c4-soft.springaddons.oidc.client.oauth2-redirections.post-authorization-code`
- `(Server)AuthenticationFailureHandler`: the default restores the post-login failure URI saved in session and applies the `com.c4-soft.springaddons.oidc.client.oauth2-redirections.post-authorization-code`

To make it clearer, you can define default post-login URL in application properties and override it from the frontend at login time by setting a header or providing a request parameter. A frequent use case is to re-activate the current route in the frontend after authorization-code completed.

#### 1.2.4. <a name="1-2-4"/>RP-Initiated Logout
Most OpenID Providers implement the RP-Initiated Logout and expose an `end_session_endpoint` in OpenID configuration, but some, like Auth0 and Cognito don't: they have a logout mechanism which works mostly like RP-Initiated Logout but with an endpoint URI and request params to find in docs. 

Sample for registrations called `cognito-user` and `auth0-user`:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        client:
          oauth2-logout:
            cognito-user:
              uri: https://spring-addons.auth.us-west-2.amazoncognito.com/logout
              client-id-request-param: client_id
              post-logout-uri-request-param: logout_uri
            auth0-user:
              uri: ${auth0-issuer}v2/logout
              client-id-request-param: client_id
              post-logout-uri-request-param: returnTo
```

#### 1.2.5. <a name="1-2-5"/>Back-Channel Logout
Back-Channel Logout is an OpenID standard allowing a client to be notified by the authorization server with logout events initiated by other client. It is some sort of *"single sign-out"* for systems with *Single Sign On* (SSO). Keycloak is a sample of an OpenID Provider capable of emitting Back-Channel Logout to a Spring client (like a Gateway used as an OAuth2 BFF). It is disabled by default. The default internal logout URI and session cookie name can be overriden in properties:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        client:
          back-channel-logout:
            enabled: true
            # Those two are optional, defaults should work in most scenarios
            internal-logout-uri: ${gateway-uri}/logout/connect/back-channel/quiz-bff
            cookie-name: JSESSION-ID
```

#### 1.2.6. <a name="1-2-6"/>Authorities Converter
By default, a `GrantedAuthoritiesMapper` using the authorities converter bean in the application context. The default for this authorities mapper is shared with resource servers: `ConfigurableClaimSetAuthoritiesConverter`. The configuration for this converter is resolved by the `OpenidProviderPropertiesResolver` in the context.

#### 1.2.7. <a name="1-2-7"/>CSRF protection
Requests to an OAuth2 client are authorized with session cookies, which exposes it to CSRF attacks. As a consequence, **CSRF protection should always be enabled on OAuth2 clients**.

The default is the with `spring-addons-starter-oidc` as it is with `spring-boot-starter-oauth2-client` (session).

When setting `com.c4-soft.springaddons.oidc.client.csrf=cookie-accessible-from-js`, as needed by single-page and mobile applications, the CSRF token is exposed in a token and the required filter is registered.

#### 1.2.8. <a name="1-2-8"/>Multi-Tenancy
Native support for client multi-tenancy is rather limited in Spring Security: it is expected that we can provide the user with a choice of authorization servers to authenticate against, but it is not that a single user session holds several numeric identities at once: the Authentication in the security context will have the name and authorities from the last authentication.

There is an experimental support for keeping an `Authentication` instance per client registration with `com.c4-soft.springaddons.oidc.client.multi-tenancy-enabled=true`. Please explore `(Reactive)SpringAddonsAop` to figure out what it does and how it works.

#### 1.2.9. <a name="1-2-9"/>Access Control
The default access rule is set to `isAuthenticated()` with two exceptions:
- routes matching the path-matchers listed in `permit-all` property for which anonymous requests are allowed
- pre-flight requests, unless disabled in `cors` properties (`OPTIONS` requests to routes matching the path-matchers listed in CORS properties).

The most convenient way to define fine-grained access control is probably to `@Enable(Reactive)MethodSecurity` and to decorate `@RestController` methods with `@PreAuthorize`.

For those preferring access control in configuration (or when you don't write the endpoint yourself), you can expose a `@Bean` of type `ClientExpressionInterceptUrlRegistryPostProcessor` or `ClientAuthorizeExchangeSpecPostProcessor`.

#### 1.2.10. <a name="1-2-10"/>Post-Process the Client Filer-Chain
By exposing a `Client(Server)HttpSecurityPostProcessor` bean, you get complete control of the `(Server)HttpSecurity` configured in the `clientSecurityFilterChain` just before it is built. This allows to change about anything that was pre-configured.

#### 1.2.11. <a name="1-2-11"/>Add Parameters to Token Requests
Some OpenID Providers require some extra parameters on the token endpoint. Auth0 for instance expects an `audience` parameter with client-credential token requests. Such parameters can be defined under `com.c4-soft.springaddons.oidc.client.token-request-params.{registrationId}` (see FAQ for a sample).

## 2. <a name="faq"/>Frequently Asked Questions

### <a name="2-1"/>What exactly is auto-configured?
To get an exhaustive insight of what is loaded, start with `src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` which is the standard Spring Boot resource. It lists `@AutoConfiguration` files that Spring Boot will use when building the application context.

You may check the implementation of the condition on each `@AutoConfiguration` (and imported `@Configuration`) to limit your investigations to what is actually loaded in your application.

### <a name="2-2"/>Are all those beans defined by `spring-addons-starter-oidc` added to my application context?
**No!** All beans are conditional and only a few are instantiated. Which ones exactly depend on the application type (servlet or reactive), dependencies (resource server, client or both), properties and explicit beans definitions (most `spring-addons-starter-oidc` beans are `@ConditionalOnMissingBean`).

### <a name="2-3"/>Why all this fuss around authorities mapping? Can't I just keep the default using scopes?
Short answer is some OpenID Providers won't put roles in scope. 

The reason for that is it is not quite the same concept: In RBAC, a *role* is an attribute of the user, while an OAuth2 scope is an attribute of the client. Scope defines what a resource owner allows an OAuth2 client to do on his behalf on the resource server(s) included in the audience. You can think of the scope as a mask to apply on user roles.

Scopes are of interest mainly when you want to give users control on which software can access which of their resources.

Roles are of interest when you want to control which user can access which resource, idependently of the software he uses for that.

### <a name="2-4"/>How to configure a resource server to accept tokens issued for Keycloak *realms* created at runtime?
See the Multi-Tenancy section in resource server features.

### <a name="2-5"/>How to provide the `audience` parameter required by Auth0 for user login?
Add it to `com.c4-soft.springaddons.oidc.client.authorization-request-params.{registrationId}`. For instance, given an `auth0-users` registration in boot properties:
```yaml
issuer: https://dev-ch4mpy.eu.auth0.com/

spring:
  security:
    oauth2:
      client:
        provider:
          auth0:
            issuer-uri: ${issuer}
        registration:
          auth0-user:
            provider: auth0
            client-id: change-me
            client-secret: change-me
            authorization-grant-type: authorization_code
            scope: openid, offline_access
com:
  c4-soft:
    springaddons:
      oidc:
        client:
          authorization-request-params:
            auth0-user:
              audience: demo.c4-soft.com
```
Note the `auth0-user` registration ID used in both Spring Boot `registration` and addons `authorization-request-params`

### <a name="2-6"/>How to provide the `audience` parameter reuqired by Auth0 for client-credentials?
Add it to `com.c4-soft.springaddons.oidc.client.token-request-params.{registrationId}`. For instance, given an `auth0-api` registration in boot preperties:
```yaml
issuer: https://dev-ch4mpy.eu.auth0.com/

spring:
  security:
    oauth2:
      client:
        provider:
          auth0:
            issuer-uri: ${issuer}
        registration:
          auth0-api:
            provider: auth0
            client-id: change-me
            client-secret: change-me
            authorization-grant-type: client_credentials
            scope: read:users
com:
  c4-soft:
    springaddons:
      oidc:
        client:
          token-request-params:
            auth0-api:
              audience: demo.c4-soft.com
```
Note the `auth0-api` registration ID used in both Spring Boot `registration` and addons `token-request-params`

### <a name="2-7"/>Can a frontend override post-login URL?
Yes. All it has to do is provide `X-POST-LOGIN-SUCCESS-URI` & `X-POST-LOGIN-FAILURE-URI` headers or `post_login_success_uri` & `post_login_failure_uri` with the request initiating authorization-code flow.

### <a name="2-8"/>Can a frontend override post RP-Initiated Logout URL?
Yes. All it has to do is provide `X-POST-LOGOUT-SUCCESS-URI` header or `post_logout_success_uri` with the request initiating RP-Initiated Logout. This URI will be added as request parameter to the Location header redirecting to the authorization server after the session is closed on the OAuth2 client.

### <a name="2-9"/>Can a frontend override the response status for OAuth2 redirections?
Yes. `SpringAddonsOauth2(Server)RedirectStrategy`, which is the default for OAuth2 redirections, searches for a `X-RESPONSE-STATUS` header and, if any, uses it to everride the default picked in application properties.

### <a name="2-10"/>Is `iss` configuration property mandatory?
No. But be aware that with what follows, the `iss` (issuer) claim validation is disabled and that the JWT decoder will only check the token signature. As the issuer and audience should always be validated in a decently secured application, **the hacks below are not recommended**.

On a Spring `oauth2ResourceServer` with a JWT decoder, what is mandatory is to provide at least:
- one of `iss` or `jwk-set-uri` for the JWT decoder to be provided with a JWK-set (the JWK-set URI is exposed in the OpenID configuration usually available from `{iss}/.well-known/openid-configuration`, reason for the `jwk-set-uri` property to be optional when `iss` property is provided and its value accessible on the network)
- an `OpenidProviderPropertiesResolver` to retrieve the configuration (and the associated JWT decoder) from token claims. The default matching `iss` claim to `iss` property, if the later is not provided (or is not exactly the value in tokens like in a "dynamic" multi-tenant scenario), then you need to expose your own `OpenidProviderPropertiesResolver` bean.

Note that if the issuer is not provided in conf, the JWT decoder is not configured with an issuer validator. Unless audience is provided, the only validator is the signature one (using the JWK-set). Sample:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - jwk-set-uri: https://oidc.c4-soft.com/auth/realms/quiz/protocol/openid-connect/certs
```
```java
@Component
public class FirstOpenidProviderPropertiesResolver implements OpenidProviderPropertiesResolver {
    private final Optional<OpenidProviderProperties> opProperties;
    
    public FirstOpenidProviderPropertiesResolver(SpringAddonsOidcProperties properties) {
        this.opProperties = properties.getOps().isEmpty() ? Optional.empty() : Optional.of(properties.getOps().get(0));
    }

    @Override
    public Optional<OpenidProviderProperties> resolve(Map<String, Object> claimSet) {
        return opProperties;
    }
}
```
This seems dumb but will work in a single tenant scenario: the 1st (and only) OpenID Provider properties group is always matched and only tokens signed by the issuer we trust are considered valid.

On a Spring OAuth2 client with `oauth2Login`, OpenID auto-configuration relies on the *Issuer Identifier* to be set as `spring.security.oauth2.client.provider.{provider-id}.issuer-uri`. If for some reason the authorization server is not accessible using the *Issuer Identifier* (misconfigured containerized environments) or does not match the OpenID spec (Microsoft), we should leave the `issuer-uri` empty, and manually provide URIs for `authorization`, `token`, `jwk-set`, and `userinfo` endpoints instead of relying on OpenID auto-configuration.

### <a name="2-11"/>Why can't I get things working easily with Microsoft authorization servers?
Microsoft authorization servers (like Entra ID, formerly known as Azure Active Directory, or AAD, or Azure AD B2C, etc.),  look like OIDC Providers but aren't with the V1 token format, which is the default.

[The OIDC discovery spec](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig) states that *"OpenID Providers supporting Discovery MUST make a JSON document available at the path formed by concatenating the string `/.well-known/openid-configuration` to the Issuer"*. Also, [the OpenID token validation spec](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) requires that *"The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim"*.

To have Microsoft Entra ID follow these OIDC discovery & OpenID token specifications requirements and issue JWT access token, we should:
- set `api.requestedAccessTokenVersion: 2` under `Applications` -> `App registrations` -> `{appName}` -> `Manifest` -> `Microsoft Graph App Manifest (New)` in Entra admin console
- ensure that hybrid flow is completely deactivated
- declare an audience (*"API"* in Entra admin console) and request it as scope with the authorization request (authorization request should contain `scope=openid {apiId}`) 

Intuitive...

### <a name="usage"/>3. Basic Usage

This section describes only the most basic usage. For advanced auto-configuration and defaults overrides, please refer to section [1. Features](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc#spring-addons-starter-oidc).

**If you are not absolutely sure why you need an OAuth2 client with `oauth2Login` (secured with sessions, not access tokens) or an OAuth2 resource server configuration (secured with access tokens, not sessions, but without `oauth2Login`), please read the [OAuth2 essentials section](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials#1-oauth2-essentials) of the tutorials.** This might save you a lot of time and effort.

Add `com.c4-soft.springaddons:spring-addons-starter-oidc` to your dependencies, in addition to `org.springframework.boot:spring-boot-starter-oauth2-client` or `org.springframework.boot:spring-boot-starter-oauth2-resource-server`.

If configuring an OAuth2 client (with `oauth2Login`), define the standard Spring Boot `provider` and `registration` properties for OAuth2 clients.

If configuring an OAuth2 resource server with access token introspection, define the standard Spring Boot `opaquetoken` properties.

Then, define the relevant `com.c4-soft.springaddons.oidc` properties for your use case. There are many complete [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples) and [tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials) you should refer to, but here are a few demos for different use-cases and OpenID Providers:

### <a name="3-1"/>3.1. Resource Server with JWT decoder

For a REST API secured with JWT access tokens, you need:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <!-- For a reactive application, use spring-boot-starter-webflux instead -->
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>

<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-oidc</artifactId>
</dependency>
```
And
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: https://oidc.c4-soft.com/auth/realms/master
          username-claim: preferred_username
          authorities:
          - path: $.realm_access.roles
          - path: $.resource_access.*.roles
        resourceserver:
          permit-all:
          - "/greet/public"
          cors:
          - path: /**
            allowed-origin-patterns: http://localhost:4200
```
Above configuration will create an application without sessions nor CSRF protection, and 401 will be answered to unauthorized requests to protected resources.

### <a name="3-2"/>3.2. Client

For an app serving Thymeleaf templates with login and logout:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <!-- For a reactive application, use spring-boot-starter-webflux instead -->
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>

<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-oidc</artifactId>
</dependency>
```
And
```yaml
cognito-issuer: https://cognito-idp.us-west-2.amazonaws.com/us-west-2_RzhmgLwjl
cognito-client-id: change-me
cognito-secret: change-me

spring:
  security:
    oauth2:
      client:
        provider:
          cognito:
            issuer-uri: ${cognito-issuer}
        registration:
          cognito-authorization-code:
            authorization-grant-type: authorization_code
            client-id: ${cognito-client-id}
            client-secret: ${cognito-secret}
            provider: cognito
            scope: openid,profile,email,offline_access
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: ${cognito-issuer}
          username-claim: username
          authorities:
          - path: cognito:groups
        client:
          security-matchers:
          - /**
          permit-all:
          - /login/**
          - /oauth2/**
          - /
          # Auth0 and Cognito do not follow strictly the OpenID RP-Initiated Logout spec and need specific configuration
          oauth2-logout:
            cognito-authorization-code:
              uri: https://spring-addons.auth.us-west-2.amazoncognito.com/logout
              client-id-request-param: client_id
              post-logout-uri-request-param: logout_uri
```
Above configuration will create an application secured with sessions (not access tokens), with CSRF protection enabled, and unauthorized requests to protected resources will be redirected to login.

### <a name="3-3"/>3.3. Client and Resource Server

For an app exposing publicly both
- Thymeleaf templates secured with session (with login and logout), all templates being served with `/ui` prefix (but index which is at `/`)
- a REST API secured with access token
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <!-- In a reactive application, use only spring-boot-starter-webflux -->
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <!-- Used for WebClient to call the REST API from controllers serving Thymeleaf templates -->
    <artifactId>spring-boot-starter-webflux</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>

<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-oidc</artifactId>
</dependency>
```
And
```yaml
auth0-issuer: https://oidc.c4-soft.com/auth/realms/master
auth0-client-id: change-me
auth0-secret: change-me

spring:
  security:
    oauth2:
      client:
        provider:
          auth0:
            issuer-uri: ${auth0-issuer}
        registration:
          auth0-authorization-code:
            authorization-grant-type: authorization_code
            client-id: ${auth0-client-id}
            client-secret: ${auth0-secret}
            provider: auth0
            scope: openid,profile,email,offline_access
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: ${auth0-issuer}
          username-claim: $['https://c4-soft.com/user']['name']
          authorities:
          - path: $['https://c4-soft.com/user']['roles']
          - path: $.permissions
        client:
          security-matchers:
          - /login/**
          - /oauth2/**
          - /logout
          - /
          - /ui/**
          permit-all:
          - /login/**
          - /oauth2/**
          - /
          # Auth0 and Cognito do not follow strictly the OpenID RP-Initiated Logout spec and need specific configuration
          oauth2-logout:
            auth0-authorization-code:
              uri: ${auth0-issuer}v2/logout
              client-id-request-param: client_id
              post-logout-uri-request-param: returnTo
          # Auth0 requires an "audience" parameter in authorization-code request to deliver JWTs
          authorization-request-params:
            auth0-authorization-code:
            - name: audience
              value: demo.c4-soft.com
        resourceserver:
          permit-all:
          - "/greet/public"
```
With the above configuration, two distinct security filter-chains will be defined:
- a client one with sessions (and CSRF protection enabled), intercepting all requests to UI templates as well as those involved in login and logout, and redirecting to login unauthorized requests to protected templates.
- a resource server one acting as default (with lowest precedence to process all requests that were not matched with client filter-chain `securityMatchers`), without sessions (requests are secured with JWT access tokens) nor CSRF protections, and returning 401 to unauthorized requests to protected resources.
