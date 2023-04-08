**There is a braking change in starters properties in 6.1.0**. Authorities-mapping configuration has changed. See [Release Notes](#release-notes).

The OAuth2 client features introduced with 6.1 (boot starters & tutorials) are getting mature. Usage is illustrated in [BFF](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/bff) and [Resource Server & Client](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_ui) tutorials. It comes with pretty cool features like [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) for "almost" standard OPs (like Auth0 or Cognito) and also [Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html) implementation.

`@WithMockKeycloakAuth`, to be used with the [deprecated Keycloak libs for spring](https://github.com/keycloak/keycloak/discussions/10187), is not provided any-more in 6.x (it is still available from 5.x): Keycloak libs are too far behind. Generic OpenID resource-server starters from this lib have been used with Keycloak for more than two years now, including in production.

Do not hesitate to fork this repo and send pull requests, even for things as small as a typo in READMEs or Javadoc. This would promote you as contributor.

# Spring-addons
The libraries hosted in this repo shine in two domains:
- provide with annotations to mock OAuth2 `Authentication` during tests (`@WithMockJwtAuth`, `@WithOAuth2Login`, `@WithMockBearerTokenAuthentication`, etc.), which allow to test method security on any `@Component`. Details below.
- push Spring Boot OAuth2 auto-configuration to the next level. As shown in **[Tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials)**, with 0 Java conf (just properties), we can configure a REST API (servlet or reactive) or an OAuth2 client (servlet or reactive, including `spring-cloud-gateway` used as BFF) with:
  * authorities mapping (source claims, prefix and case transformation), without having to provide authentication converter, user service or `GrantedAuthoritiesMapper` in each app
  * fine grained CORS configuration (per path matcher), which enables to override allowed origins as environment variable when switching from `localhost` to `dev` or `prod` environments
  * sessions & CSRF disabled by default on resource server and enabled on clients. If a cookie repo is chosen for CSRF (as required by Angular, React, Vue, etc.), then the right request handler is configured and a filter to actually set the cookie is added
  * basic access control: `permitAll` for a list of path matchers and `authenticated` as default (to be fine tuned with method security or a configuration post-processor bean)
  * for clients only:
    - logout success handler for OPs not strictly following the standard (exotic parameter names or missing `end_session_endpoint` in OpenID configuration). Auth0 and Amazon Cognito are samples of such OPs.
    - an implementation for client side of the Back-Channel Logout
    - client host and port explicitly provided in login configuration to avoid [redirection issues when the client does not use 8080 (or 8443 if SSL is enabled)](https://github.com/spring-projects/spring-security/issues/12307)

Jump to:
- [1.  Unit & Integration Testing With Security](#unit-tests)
- [2. Spring Boot OAuth2 Starters](#oauth2-starters)
- [3. Where to Start](#start)
- [4. Versions & Requirements](#versions)
- [5. Additional Modules](#additional-modules)
- [6. Release Notes](#release-notes)
- [7. Maven-Central Reminders](#maven-central)

## 1. <a name="unit-tests"/>Unit & Integration Testing With Security
Testing method security (`@PreAuthorize`, `@PostFilter`, etc.) requires to configure the security context. `Spring-security-test` provides with `MockMvc` request post-processors and `WebTestClient` mutators to to do so, but this requires the context of a request, which limits its usage to testing secured controllers.

To test method security on any type of `@Component` (`@Controller`, off course, but also `@Service` and `@Repository`) there are  only two options: build tests security context by yourself and populate it with stubbed / mocked authentications, or use annotations.

An [article covering the usage of OAuth2 test annotations from this lib](https://www.baeldung.com/spring-oauth-testing-access-control) was published on Baeldung. This, along with all [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples) and [tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials) source-code (which contain a lot of unit and integration testing), should be enough to get you started.

## 2. <a name="oauth2-starters"/>Spring Boot Starters
This repo contains thin wrappers around `spring-boot-starter-oauth2-resource-server` or `spring-boot-starter-oauth2-client`:
- [spring-addons-webflux-client](https://github.com/ch4mpy/spring-addons/tree/master/webflux/spring-addons-webflux-client) to be used in reactive applications rendering templates on the server (Thymeleaf, JSF, etc.), **or in `spring-cloud-gateway` used as BFF** (server-side OAuth2 confidential client securing a browser application with sessions and replacing session cookies with OAuth2 access tokens before forwarding requests from browsers to resource servers)
- [spring-addons-webflux-introspecting-resource-server](https://github.com/ch4mpy/spring-addons/tree/master/webflux/spring-addons-webflux-introspecting-resource-server) to be used in reactive REST APIs secured with access token introspection
- [spring-addons-webflux-jwt-resource-server](https://github.com/ch4mpy/spring-addons/tree/master/webflux/spring-addons-webflux-jwt-resource-server) to be used in **reactive REST APIs secured with JWT decoders**
- [spring-addons-webmvc-client](https://github.com/ch4mpy/spring-addons/tree/master/webmvc/spring-addons-webmvc-client) to be used in servlet applications rendering templates on the server (Thymeleaf, JSF, etc.)
- [spring-addons-webmvc-introspecting-resource-server](https://github.com/ch4mpy/spring-addons/tree/master/webmvc/spring-addons-webmvc-introspecting-resource-server) to be used in servlet REST APIs secured with access token introspection
- [spring-addons-webmvc-jwt-resource-server](https://github.com/ch4mpy/spring-addons/tree/master/webmvc/spring-addons-webmvc-jwt-resource-server) to be used in **servlet REST APIs secured with JWT decoders**

This starters are designed to push auto-configuration one step further. In most cases, you should need 0 Java conf. An effort was made to make [tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials), Javadoc and modules READMEs as informative as possible. Please refer there for more details.

## 3. <a name="start"/>Where to Start
[Tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials) which cover:
- just enough OAuth2 theory
- dev environment configuration (SSL certificate, Keycloak)
- various resource-servers security configuration scenarios
- security rules unit-testing

[Samples](https://github.com/ch4mpy/spring-addons/tree/master/samples) cover:
- `@Controller`, `@Service` and `@Repository` **unit testing**
- **integration testing** (`@SpringBootTest`) with mocked authentication
- all combinations with choices from the following 3 points:
  * webmvc / webflux
  * JWT decoder / access token introspection
  * `OAuthentication<OpenidClaimSet>` / Spring default `Authentication` implementation (`JwtAuthenticationToken` for JWT decoder or `BearerTokenAuthentication` for token introspection)

## 4. <a name="versions"/>Versions & Requirements
6.x branch is designed for spring-boot 3 and requires JDK 17 as minimum.

If locked wtih a lower JDK or spring-boot version, you'll have to use a 5.4.x release wich are made with **JDK 1.8** and spring 2.6 (boot auto loading mechanisms have change with 2.7). But be aware that some of the features documented on main branch can be missing or behave differently.

I could forget to update README before releasing, so please refer to [maven central](https://repo1.maven.org/maven2/com/c4-soft/springaddons/spring-addons/) to pick latest available release
```xml
    <properties>
        <springaddons.version>6.1.7</springaddons.version>
        <app-type>webmvc</app-type><!-- alternative value is webflux !-->
        <token>jwt</token><!-- alternative value is introspecting !-->
    </properties>
    <dependencies>

        <!-- to pull resource-server stater with its companion for unit-tests -->
        <dependency>
            <groupId>com.c4-soft.springaddons</groupId>
            <artifactId>spring-addons-${app-type}-${token}-resource-server</artifactId>
            <version>${springaddons.version}</version>
        </dependency>
        <dependency>
            <groupId>com.c4-soft.springaddons</groupId>
            <artifactId>spring-addons-${app-type}-${token}-test</artifactId>
            <version>${springaddons.version}</version>
            <scope>test</scope>
        </dependency>

        <!-- If you don't want starters but need @WithMockJwtAuth or WithMockBearerTokenAuthentication -->
        <!-- instead of the two preceding, you can pull test annotations only -->
        <dependency>
            <groupId>com.c4-soft.springaddons</groupId>
            <artifactId>spring-addons-oauth2-test</artifactId>
            <version>${springaddons.version}</version>
        </dependency>

    </dependencies>
```

## 5. <a name="additional-modules"/>Additional Modules

### 5.1. [archetypes](https://github.com/ch4mpy/spring-addons/tree/master/archetypes)
A set of archetypes for webflux and webmvc apps, initiated either as multi or single module maven projects.
All generate projects focused on REST micro-services:
- Servlet or reactive @RestController
- OpenID security
- default conf providing with enabled CORS, "stateless" sessions (user "session" state in access token only), disabled CSRF (because no session on the resource-server), 401 instead of redirect to login, ...
- Spring exception-handling
- spring-native for smaller / faster booted services
- bootstraped JPA and unit tests

### 5.2. [starters](https://github.com/ch4mpy/spring-addons/tree/master/starters)
A set of re-usable `@Components` (mostly `@Service` and `@ConfigurationProperties`) with spring-boot `@AutoConfiguration`:
- [WebClient.Builder](https://github.com/ch4mpy/spring-addons/tree/master/starters/spring-addons-starters-webclient) factory  with proxy configuration from properties
- [reCAPTCHA](https://github.com/ch4mpy/spring-addons/tree/master/starters/spring-addons-starters-recaptcha)
Uses Webclient starter to provide with Google reCAPTCHA validation Service (secret & proxy configuration from properties)

Using such libs is dead simple: just declare depedency on one of those libs and use @Components just as if were declared in your app package (define properties and auto-wire components as usual in your boot project).

## 6. <a name="release-notes"/>Release Notes

2.0 comes with a noticeable amount of breaking changes. So lets start tracking features.


### 6.1.7
- create `ServletConfigurationSupport` and `ReactiveConfigurationSupport` in `spring-addons-{webmvc|webflux}-core` to remove code duplication from starters

### 6.1.5
- add new helpers to type private claims in test annotations for `Double`, `URIs`, `URLs` and `Date`
- add 1 level of nested claims to `@Claims`, the test annotation to define private claims in OAuth2 test annotations. It is not possible to describe recursive structures with annotation (annotation with a node of the same type as itself), which is an issue to describe a JSON document. To configure further nested claims, it is still possible to use `@JsonObjectClaim` with serialized JSON strings. Sample usage with all possible types of claims (hopefully, it will never be necessary to configure as many claims in a single test):
```java
@WithMockJwtAuth(authorities = "ROLE_AUTHORIZED_PERSONNEL", claims = @OpenIdClaims(sub = "Ch4mpy", otherClaims = @Claims(
        intClaims = { @IntClaim(name = "int1", value = 42), @IntClaim(name = "int2", value = 51) },
        longClaims = { @LongClaim(name = "long1", value = 42), @LongClaim(name = "long2", value = 51) },
        doubleClaims = { @DoubleClaim(name = "double1", value = 4.2), @DoubleClaim(name = "double2", value = 5.1) },
        stringClaims = { @StringClaim(name = "str1", value = "String 1"), @StringClaim(name = "str2", value = "String 2") },
        uriClaims = { @StringClaim(name = "uri1", value = "https://localhost:8080/greet"), @StringClaim(name = "uri2", value = "https://localhost:4200/home#greet") },
        urlClaims = { @StringClaim(name = "url1", value = "https://localhost:8080/greet"), @StringClaim(name = "url2", value = "https://localhost:4200/home") },
        epochSecondClaims = { @IntClaim(name = "epoch1", value = 1670978400), @IntClaim(name = "epoch2", value = 1680648172)},
        dateClaims = { @StringClaim(name = "date1", value = "2022-12-14T00:40:00.000+00:00"), @StringClaim(name = "date1", value = "2023-04-04T00:42:00.000+00:00") },
        stringArrayClaims = { @StringArrayClaim(name = "strArr1", value = { "a", "b", "c" }), @StringArrayClaim(name = "strArr2", value = { "D", "E", "F" }) },
        jsonObjectClaims = { @JsonObjectClaim(name = "obj1", value = obj1), @JsonObjectClaim(name = "obj2", value = obj2)},
        jsonObjectArrayClaims = @JsonObjectArrayClaim(name = "objArr1", value = { obj3, obj4}),
        nestedClaims = { @NestedClaims(
                name = "https://c4-soft.com/spring-addons",
                intClaims = { @IntClaim(name = "nested_int1", value = 42), @IntClaim(name = "nested_int2", value = 51) },
                longClaims = { @LongClaim(name = "nested_long1", value = 42), @LongClaim(name = "nested_long2", value = 51) },
                doubleClaims = { @DoubleClaim(name = "nested_double1", value = 4.2), @DoubleClaim(name = "nested_double2", value = 5.1) },
                stringClaims = { @StringClaim(name = "nested_str1", value = "String 1"), @StringClaim(name = "nested_str2", value = "String 2") },
                uriClaims = { @StringClaim(name = "nested_uri1", value = "https://localhost:8080/greet"), @StringClaim(name = "nested_uri2", value = "https://localhost:4200/home#greet") },
                urlClaims = { @StringClaim(name = "nested_url1", value = "https://localhost:8080/greet"), @StringClaim(name = "nested_url2", value = "https://localhost:4200/home") },
                epochSecondClaims = { @IntClaim(name = "nested_epoch1", value = 1670978400), @IntClaim(name = "nested_epoch2", value = 1680648172)},
                dateClaims = { @StringClaim(name = "nested_date1", value = "2022-12-14T00:40:00.000+00:00"), @StringClaim(name = "nested_date1", value = "2023-04-04T00:42:00.000+00:00") },
                stringArrayClaims = { @StringArrayClaim(name = "nested_strArr1", value = { "a", "b", "c" }), @StringArrayClaim(name = "nested_strArr2", value = { "D", "E", "F" }) },
                jsonObjectClaims = { @JsonObjectClaim(name = "nested_obj1", value = obj1), @JsonObjectClaim(name = "nested_obj2", value = obj2)},
                jsonObjectArrayClaims = @JsonObjectArrayClaim(name = "nested_objArr1", value = { obj3, obj4}))})))
```

### 6.1.4
- gh-106: Properties to disable spring-addons security filter-chain auto-configuration:
  * for clients: empty path-matchers array or `com.c4-soft.springaddons.security.client.enabled=false`
  * for resource servers: `com.c4-soft.springaddons.security.enabled=false`

### 6.1.3
- fix CSRF protection configuration (apply https://docs.spring.io/spring-security/reference/5.8/migration/servlet/exploits.html#_i_am_using_a_single_page_application_with_cookiecsrftokenrepository and https://docs.spring.io/spring-security/reference/5.8/migration/reactive.html#_i_am_using_angularjs_or_another_javascript_framework)
- rework the Javadoc and README of all 6 OAuth2 starters
- introduce a Back-Channel Logout client implementation to both client starters
- rework BFF and resource server & client tutorials with spring-addons client starters

### 6.1.2
- boot 3.0.4
- add a BFF tutorial

### 6.1.1
- add [spring-addons-webmvc-client](https://github.com/ch4mpy/spring-addons/tree/master/webmvc/spring-addons-webmvc-client)
- add [spring-addons-webflux-client](https://github.com/ch4mpy/spring-addons/tree/master/webflux/spring-addons-webflux-client)
- in both client starters, add a logout handler for OP with RP-Initiated logout implementations which do not comply with OIDC standard. This handler is configurable from properties (logout end-point and post-logout URIs). See [`resource-server_with_ui` tutorial](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_ui) for details.

### 6.1.0
- **breaking change in properties:** authorities mapping is now configured per claim JSON path (instead of per issuer). This enables to use different prefix (and case) for different claims (for instance `SCOPE_` for `scope` claim and `ROLE_` for `realm_access.roles` one). As a consequence, `com.c4-soft.springaddons.security.issuers[].authorities.claims[]` is replaced with `com.c4-soft.springaddons.security.issuers[].authorities[].path`.Also, `prefix` as well as `case` are put at the same level as (JSON) `path`.

Sample migration with YAML:
```yml
com:
  c4-soft:
    springaddons:
      security:
        issuers:
        - location: ${keycloak-issuer}
          username-claim: preferred_username
          authorities:
            prefix: ROLE_
            claims:
            - realm_access.roles
            - resource_access.client1.roles
```
Becomes:
```yml
com:
  c4-soft:
    springaddons:
      security:
        issuers:
        - location: ${keycloak-issuer}
          username-claim: $.preferred_username
          authorities:
          - path: $.realm_access.roles
            prefix: ROLE_
          - path: $.resource_access.client1.roles
            prefix: ROLE_
```
- "pseudo" JSON path for username and authorities claims is now actual JSON path. This means that `$.resource_access.*.roles` will be successfully accepted. Thanks to JSON path syntax, this is not a breaking change (`$.resource_access.client1.roles` and `resource_access.client1.roles` are interpreted the same)
- bump to Spring Boot 3.0.3

### 6.0.16
- Add a `username-clame` configuration property to define, per issuer, from which claim of the access token should be retrieved the username (what is returned by `Authentication::getName`). Default is subject for backward compatibility

### 6.0.15
### 5.4.2
- [gh-100](https://github.com/ch4mpy/spring-addons/issues/100) prevent a NPE in reactive resource-server using JWT spring-addons starter when the issuer in an access token is not listed in conf. All credits go to [lArtiquel](https://github.com/lArtiquel) who spotted the bug and submitted the fix.

### 6.0.13
- create `ServerHttpRequestSupport` and `HttpServletRequestSupport` to help statically access to the request in current context (usage in authentication converters for instance

### 6.0.12
- add `@WithOAuth2Login` and `@WithOidcLogin` to populate test security-context with an `OAuth2AuthenticationToken` instance (with respectively `DefaultOAuth2User` and `DefaultOidcUser` as principal)
- bump to spring-boot `3.0.2`
- default authorities collection in tests annotations, `MockMvc` post-processors and `WebTestClient` mutators is set to empty array (instead of `{ "ROLE_USER" }`)

### 6.0.11
- [gh-86](https://github.com/ch4mpy/spring-addons/issues/86) `OAuthentication::setDetails` [should not throw](https://github.com/spring-projects/spring-security/issues/11822) until spring-security 6.1 is released
- [gh-87](https://github.com/ch4mpy/spring-addons/issues/87) spring-addons JWT starters should start even if `spring.security.oauth2.resourceserver.jwt.issuer-uri` is set in configuration properties

### 6.0.10
- [gh-83](https://github.com/ch4mpy/spring-addons/issues/83) do not force traffic to http when SSL is not enabled (just force https when SSL is enabled)

### 6.0.9
- Make OAuthentication immutable

### 6.0.7
- release with spring-boot 3.0.0 GA as transitive dependency

### 6.0.1
- [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples) for all combinations of:
  * webmvc / webflux
  * JWT decoder / access token introspection
  * `OAuthentication<OpenidClaimSet>` / Spring default `Authentication` implementation (`JwtAuthenticationToken` for JWT decoder or `BearerTokenAuthentication` for token introspection)
- minor fixes (@WithMockAuthentication and reactive + introspection starter)

### 6.0.0
- Switch to spring-boot 3 (and spring-security 6)
- Stop supporting the [very deprecated Keycloak libs for spring](https://github.com/keycloak/keycloak/discussions/10187)

### 5.4.0
- Use a single bean name for
  * `ServletSecurityBeans` and `ReactiveSecurityBeans`: AddonsSecurityBeans
  * `@AutoConfigureAddonsSecurity{Webmvc|Weblux}{Jwt|Introspecting}`: `@AutoConfigureAddonsSecurity`
- Add `@AutoConfigureAddonsWebSecurity` to do the same as existing `@AutoConfigureAddonsSecurity` which now loads authorities converter only (useful to unit-test @Components that are not @Controller).
- More options for CSRF configuration (enum property instead of a boolean) and CSRF disabled by default when session-management is state-less.
- Compatibility with JDK 1.8 and spring-boot 2.6 (get version 6.x for spring-boot 3 and JDK 17)
- webflux dependencies cleanup (were pulling some servlet dependencies)
- All samples now demo @Service and @Repository unit-tests in addition to @Controller ones.

### 5.3.0
Use `JwtAuthenticationToken` or `BearerAuthenticationToken` by default in  resource-server starters. For some reason, `OAuthentication<OpenidClaimSet>` frightens rookies.
- make `OAuth2AuthenticationFactory` `@Bean` optional.
- remove `OAuth2ClaimsConverter` (interface definition and @ConditionalOnMissingBean)
- remove the recently added `oauth2-authentication-factory-enabled` property (instead, evaluate if an `OAuth2AuthenticationFactory` bean was provided)

### 5.2.2
- resource-server starter main beans (`Security(Web)FilterChain`) are no-longer "conditional on missing": if you dan't want it, don't pull starter lib.
- add `oauth2-authentication-factory-enabled` flag to easily fall-back to Spring default OAuth2 `Authentication` implementations (`JwtAuthenticationToken` and `BearerTokenAuthentication` for resource-servers with respectively JWT decoder or opaque token introspection)

### 5.1.3
- keycloak 19
- release with JDK 17 and boot 2.7.2
- release with JDK 1.8 and boot 2.6.10

### 5.1.0
- Support token introspection for resource-servers.
- Rename `spring-addons-*-jwt-resource-server-test` to `spring-addons-*-test` as it apply for both JWT and introspection

### 5.0.0
Rename modules to:
- have all module names start with `spring-addons` prefix, then intermediate module if any (`archetypes`, `samples`, `starters`, `webmvc` or `webflux`) and last what leaf module aims at
- better reflect what it do

For instance, `spring-security-oauth2-webmvc-addons` only applies to resource-servers secured with JWTs (not to opaque tokens) -> renamed to `spring-addons-webmvc-jwt-resource-server`

Rename `com.c4-soft.springaddons.security.token-issuers` configuration properties to `com.c4-soft.springaddons.security.issuers` for the same reason: only accepts JWT token issuers (and not opaque token issuers with introspection end-point for instance)

### 4.5.0
CSRF enabled by default, using `CookieCsrfTokenRepository` if session management is "stateless".

### 4.4.4
[gh-53 GenericMethodSecurityExpressionHandler should accept expression root suppliers for many authentication type](https://github.com/ch4mpy/spring-addons/issues/53)

### 4.4.2
add [reCAPTCHA validation spring-boot starter](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starters-recaptcha)

### 4.4.1
rename `@WithMockOidcAuth` to shorter and more expressive `@OpenId`: it populates test security context with an OAuth2 `Àuthentication` containing an OpenID claim-set

### 4.4.0
- rename `OpenidClaimSet` to `OpenidClaimSet`: more expressive as this class contains OpenID token claims only
- rename `OAuthentication` to `OAuthentication`: it has no more adherence to OpenID (just specific to authentication with encoded claims in a bearer string)

### 4.3.2
Slight properties rework. Now, to configure issuers and authorities mapping:
```
# should be set to where your authorization-server is
com.c4-soft.springaddons.security.issuers[0].location=https://localhost:8443/realms/master

# should be configured with a list of private-claims this authorization-server puts user roles into
# below is default Keycloak conf for a `spring-addons` client with client roles mapper enabled
com.c4-soft.springaddons.security.issuers[0].authorities.claims=realm_access.roles,resource_access.spring-addons-public.roles,resource_access.spring-addons-confidential.roles

# use IDE auto-completion or see SpringAddonsSecurityProperties javadoc for complete configuration properties list
```
where `caze` is one of `unchanged`, `upper` or `lower`

### 4.3.0
- [gh-50](https://github.com/ch4mpy/spring-addons/issues/50): One entry per authorization-server for authorities mapping (see samples `application.properties` files for new configuration structure).
- [gh-51](https://github.com/ch4mpy/spring-addons/issues/51): Group archetypes, webmvc and webflux modules.

### 4.2.1
- [gh-49](https://github.com/ch4mpy/spring-addons/issues/49): Samples in dedicated modules. All samples are moved from libs tests to [`samples`](https://github.com/ch4mpy/spring-addons/tree/master/samples) module, with one sub-module per sample.

### 4.2.0
Cleanup and prepare for spring-boot 3:
- [gh-46](https://github.com/ch4mpy/spring-addons/issues/46): split webmvc & webflux content from `spring-addons-oauth2` 
- [gh-47](https://github.com/ch4mpy/spring-addons/issues/47): provide `SecurityFilterChain` bean instead of extending `WebSecurityConfigurerAdapter`
- [gh-48](https://github.com/ch4mpy/spring-addons/issues/48): make use of spring-boot `@AutoConfiguration`

### 4.1.5
- Replace multiple JWT issuers JwtDecoder (from 4.1.4) with `AuthenticationManagerResolver` @Beans 

### 4.1.4
- JwtDecoder for configuring multiple JWT issuers (single resource server accepting IDs from two or more authorization-servers)

### 4.1.3
- finer configuration control with `SpringAddonsSecurityProperties`

### 4.0.0
- move keycloak related code to `spring-addons-keycloak`

### 3.2.0
- Master branch back to single JDK: 17
- Create `jdk1.8` and `jdk11` branches

### 3.1.16
- Add [spring-addons-archetypes-webmvc-multimodule](https://github.com/ch4mpy/spring-addons/blob/master/spring-addons-archetypes-webmvc-multimodule) to boostrap native-ready Spring REST API with webmvc, JPA, OpenAPI and OpenID security.

### 3.1.13
- Add a [sample](https://github.com/ch4mpy/spring-addons/blob/master/custom-oidc-authentication-impl.MD) with `OpenidClaimSet` specialisation (parse private claims in addition to authorities).

### 3.1.12
- Improve `OidcReactiveApiSecurityConfig` and `OidcServletApiSecurityConfig` usability: ease security beans replacement (including authorities and authentication converter for use cases where OAuthentication is not enough)

### 3.1.11
- Rename `SecurityProperties` to less conflicting `SpringAddonsSecurityProperties`

### 3.1.10
- Turn `AbstractOidc...ApiSecurityConfig` into `Oidc...ApiSecurityConfig` with default authorities mapper being keycloak or Auth0 depending on `com.c4-soft.springaddons.security.keycloak.client-id` being set or not
- More CORS and authorities mapping configuration in `SecurityProperties`

### 3.1.8
- Fix missing JTI claim mapping from `@OpenIdClaims` ([gh-35](https://github.com/ch4mpy/spring-addons/issues/35)).

### 3.1.7
- Add `AbstractOidcReactiveApiSecurityConfig` to `spring-addons-oauth2`. It provides with reasonable default WebSecurityConfig for a reactive (weblux) based API secured with OAuthentication.

### 3.1.6
- Add `AbstractOidcServletApiSecurityConfig` to `spring-addons-oauth2`. It provides with reasonable default WebSecurityConfig for a servlet based API secured with OAuthentication.

### 3.1.4
- lombok with provided scope ([gh-31](https://github.com/ch4mpy/spring-addons/issues/31))

### 3.1.3
- spring-boot 2.6.1
- release with JDK version (compilation and runtime target)

### 3.1.0
- spring-boot 2.6

### 3.0.0
- in OAuth2 related test annotations all claims are now grouped under a single `claims = @OpenIdClaims(...)`
- `@WithMockJwtAuth` in addition to `@WithMockKeycloakAuth` and `@WithMockOidcAuth`
- some code cleanup, quite a bunch of code removed and some renaming (including breaking changes, reason for new major version)

### 2.6.6

- import spring-boot 2.5.5 BOM (instead of inheriting 2.5.4 POM)

### 2.6.5

- Downgrade Java compatibility to 1.8

### 2.6.1

- spring-boot 2.5.4

### 2.6.0

- replace `KeycloakOidcIdAuthenticationConverter` with `SynchronizedJwt2OidcIdAuthenticationConverter` and complement it with `ReactiveJwt2OidcIdAuthenticationConverter`
- remove references to Keycloak from `spring-addons-oauth2` (implementations where mostly useless)

### 2.5.4

- bump Keycloak BOM to 14.0.0

### 2.5.3

- bump spring-boot to 2.5

### 2.5.1

- introduce `@JsonObjectClaim` and `@JsonArrayClaim` to configure complex private claims. Sample: `@WithMockKeycloakAuth(otherClaims = @ClaimSet(jsonObjectClaims = @JsonObjectClaim(name = "foo", value = "{\"bar\":\"bad\", \"nested\":{\"deep\":\"her\"}, \"arr\":[1,2,3]}")))` or `@WithMockOidcId(privateClaims = @JsonObjectClaim(name = "foo", value = "{\"bar\":\"bad\", \"nested\":{\"deep\":\"her\"}, \"arr\":[1,2,3]}"))`

### 2.4.1

- [issue #14](https://github.com/ch4mpy/spring-addons/issues/14) added jti and nbf (from JWT spec) to @IdTokenClaims (an ID token is a JWT)
- [issue #14](https://github.com/ch4mpy/spring-addons/issues/14) added session_state to @IdTokenClaims as per https://openid.net/specs/openid-connect-session-1_0.html#CreatingUpdatingSessions
- [issue #14](https://github.com/ch4mpy/spring-addons/issues/14) rename `privateClaims` to `otherClaims` in `@WithMockKeycloakAuth`
- [issue #15](https://github.com/ch4mpy/spring-addons/issues/15) `GrantedAuthoritiesMapper` is now optional in test config. Defaulted to `NullAuthoritiesMapper`

### 2.4.0

- rename `ServletKeycloakAuthUnitTestingSupport::keycloakAuthenticationToken()` to `authentication()` to improve API fluidity (`api.with(keycloak.authentication()).get(...)`)

### 2.3.0

- implementation closer to [open ID specs](https://openid.net/specs/openid-connect-core-1_0.html): split claims into `@IdTokenClaims` and `@OidcStandardClaims`
- re-use OIDC ID annotations into `@WithMockKeycloakAuth`

### 2.2.0

- `OidcId::getName()` returns `subject` claim instead of `preferred_username`
- replace `name` with `subject` in `@WithMockOidcId`
- replace `name` from `@WithMockKeycloakAuth` with `preferedUsername` in `@WithAccessToken`
- support for private claims in `@WithMockOidcId` and `@WithMockKeycloakAuth` (claims with values of type `int`, `long`, `String` and `String[]` only)
- add missing subject claim in Keycloak access and ID tokens
- compose `@WithAccessToken` with `@WithKeycloakIDToken` instead of repeting properties (`AccessToken` extends `IDToken`)
- add advanced `@WithMockKeycloakAuth` sample usage in [`spring-addons-oauth2-test` README](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2-test)

### 2.1.0

- fix Keycloak typo (was wrongly spelled Keycloack at many places)
- add samples with authrities retieved from a DB instead of the JWT for both OAuthentication and JwtAuthenticationToken
- add sample involving `keycloak-spring-boot-starter` and `keycloak-spring-security-adapter`

### 2.0.0

These release is still focused on unit-testing Spring OAuth2 applications

- `@WithMockAuthentication` annotation along with `mockAuthentication()` servlet (webmvc) and reactive (webflux) flow APIs. You choose the `Authentication` type, the framework feeds the security context with a Mockito mock. This is dead simple but should cover 99% of test cases. I wonder why I didn't think of it sooner...
- Focus solely on adding to Spring `Authentication` implementations and tests tooling (no more alternatives, with an exception for `OidcId` which overlaps Spring's `OidcIdToken`)
- Split `webmvc` (servlets) and `webflux` (reactive) code in distinct libs to ease dependency management
- Re-shuffle packages and jars (less code, less jars, more expressive package names)
- WIP: Extensives samples and tests. Samples are boot apps under `src/test` to keep jars small
- Use Keycloak as authorisation-server for all resource-server samples, each of which configuring a specific `Authentication` impl

Note that I chose Keycloak because it's a feature rich, easy to setup authorisation-server.
It should not be much of an effort to migrate sample resource-servers to another one, with an exception of those using `KeycloakAuthenticationToken` as authentication impl, of course.

## 7. <a name="maven-central"/>Maven-Central Reminders

Cheat-sheets for me when setting up a new development environment

### 7.1. GPG Sigin Key
``` bash
gpg --list-keys
# if key absent, then generate one with
gpg --gen-key
# publish public key to one of supported servers 
export GPG_PUB_KEY=(replace with "pub" key)
gpg --keyserver http://pgp.mit.edu:11371/ --send-keys $GPG_PUB_KEY
gpg --keyserver http://keyserver.ubuntu.com:11371/ --send-keys $GPG_PUB_KEY
gpg --keyserver https://keys.openpgp.org/ --send-keys $GPG_PUB_KEY
```


### 7.2. ~/.m2/settings.xml
``` xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">
  <servers>
    <server>
      <!-- OSSRH Jira account -->
      <id>ossrh</id>
      <username>ch4mpy</username>
      <password>${env.OSSRH_PWD}</password><!-- password retrieved from environment variable -->
    </server>
  </servers>

  <profiles>
    <profile>
      <id>ossrh</id>
      <activation>
        <activeByDefault>true</activeByDefault>
      </activation>
      <properties>
        <gpg.executable>gpg</gpg.executable>
        <gpg.passphrase>${env.GPG_PWD}</gpg.passphrase><!-- password retrieved from environment variable -->
      </properties>
    </profile>
  </profiles>
</settings>
```

Add-opens for releasing with JDK 17:
`export JDK_JAVA_OPTIONS='--add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.base/java.text=ALL-UNNAMED --add-opens java.desktop/java.awt.font=ALL-UNNAMED'`
