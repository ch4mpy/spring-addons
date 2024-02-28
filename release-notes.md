# Release Notes

## `7.x` Branch

### `7.6.3`
- Spring Boot 3.2.3
- add `com.c4-soft.springaddons.oidc.client.pkce-forced` property. Default to `false`. When `true`, PKCE is used by  clients for authorization-code flows, even by confidential clients
- move [the BFF tutorial to Baeldung](https://www.baeldung.com/spring-cloud-gateway-bff-oauth2). It is also refreshed and now contains sample implementations for React (Next.js) and Vue (Vite).

### `7.6.0`
- move the experimental support for `RestClient` and `WebClient` to a dedicated starter: [`spring-addons-starter-rest`](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-rest). The reasons for that are:
  * `spring-addons-starter-oidc` is not necessary to use this helpers
  * OAuth2 authorization is optional for REST clients

### `7.5.4`
- experimental support beans for `RestClient` and `WebClient`

### `7.5.3`
- [gh-188](https://github.com/ch4mpy/spring-addons/issues/188) Fix unnecessarily required audience in `JWTClaimsSetAuthenticationManagerResolver`

### `7.5.1`
- make `(Reactive)SpringAddonsOAuth2AuthorizedClientBeans` conditional on `com.c4-soft.springaddons.oidc.client.token-request-params` properties being present
- fix missing `SpringAddons(Reactive)JwtDecoderFactory` default bean

### `7.5.0`
- Create [spring-addons-starter-oidc README](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc)
- Replace `AuthoritiesMappingPropertiesResolver` with `OpenidProviderPropertiesResolver`
- `OpenidProviderPropertiesResolver` makes multi-tenancy much simpler to implement, including in "dynamic" scenarios (see [spring-addons-starter-oidc README](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starter-oidc#1-1-4))
- Fix names of `(Server)HttpSecurityPostProcessor` (synchronised impl where prefixed with `Server` which it shouldn't and reactive weren't when it should)
  * renamed `HttpSecurityPostProcessor`, `ClientHttpSecurityPostProcessor` and `ResourceServerHttpSecurityPostProcessor` from `reactive` packages to `ReactiveHttpSecurityPostProcessor`, `ClientReactiveHttpSecurityPostProcessor` and `ResourceServerReactiveHttpSecurityPostProcessor`
  * renamed `ServerHttpSecurityPostProcessor`, `ClientHttpSecurityPostProcessor` and `ResourceServerHttpSecurityPostProcessor` from `synchronized` packages to `SynchronizedHttpSecurityPostProcessor`, `ClientSynchronizedHttpSecurityPostProcessor` and `ResourceServerSynchronizedHttpSecurityPostProcessor`

### `7.4.1`
- [gh-183](https://github.com/ch4mpy/spring-addons/issues/183) Allow anonymous CORS preflight requests (`OPTIONS` requests to a path configured with CORS)
- [gh-184](https://github.com/ch4mpy/spring-addons/issues/184) Configuration properties to add parameters to token requests (necessary for instance to add an `audience` when using client-credentials with Auth0)
- Fix Back-Channel Logout activation

### `7.4.0`
- Change arrays for lists in spring-addons properties. Apparently, configuration properties meta-data is better generated for Lists...
- Fix properties documentation issues (`resource-server` instead of `resourceserver`)

### `7.3.7`
- [gh-182](https://github.com/ch4mpy/spring-addons/issues/182)doubled path-prefix by SpringAddonsServerOAuth2AuthorizationRequestResolver

### `7.3.6`
- Add a `com.c4-soft.springaddons.oidc.client.back-channel-logout.enabled` property to opt-in [Spring Security implementation of Back-Channel Logout](https://docs.spring.io/spring-security/reference/reactive/oauth2/login/logout.html#configure-provider-initiated-oidc-logout). `Customizer.withDefaults()` is used unless you provide one as a bean.

### `7.3.5`
- Boot `3.2.2` as transitive dependency

### `7.3.4`
- [gh-178](https://github.com/ch4mpy/spring-addons/issues/178) `authorization-request-params` ignored

### `7.3.3` 
- [gh-176](https://github.com/ch4mpy/spring-addons/issues/176) Exception thrown when `post-logout-redirect-path` is null
- [gh-177](https://github.com/ch4mpy/spring-addons/issues/177) Post-login success & failure URI params and headers on authentication request are ignored in reactive applications

### `7.3.2`
- [gh-174](https://github.com/ch4mpy/spring-addons/issues/174) Fix a regression on request to exchange authorization-code for tokens in servlet applications 

### `7.3.1`
- [gh-173](https://github.com/ch4mpy/spring-addons/issues/173) prevent NPE. Thanks to [@yennor](https://github.com/yennor) for finding the bug and submitting a fix.

### `7.3.0`
- [gh-166](https://github.com/ch4mpy/spring-addons/issues/166)
  * `@WithMockJwtAuth` authentication factory uses the authentication converter in the context or a `JwtAuthenticationConverter` if none is found
  * `@WithMockBearerTokenAuthentication` authentication factory uses the `OpaqueTokenAuthenticationConverter` in the context
- [gh-169](https://github.com/ch4mpy/spring-addons/issues/169) Per request post-login and post-logout URIs. It is now possible to set post-login success / failure URIs as header or request param when initiating `oauth2Login`. This URIs are saved in session and used by the default authentication success / failure handlers. Similarly, when using RP-Initiated Logout, the default logout success handler scans for a post-logout URI in headers and query params to override the default value in properties. The name for these headers, query params and session attributes are exposed by [SpringAddonsOidcClientProperties](https://github.com/ch4mpy/spring-addons/blob/master/spring-addons-starter-oidc/src/main/java/com/c4_soft/springaddons/security/oidc/starter/properties/SpringAddonsOidcClientProperties.java).

### `7.1.16`
- Spring boot `3.2.0` as transient dependency

### `7.1.15`
- [gh-155](https://github.com/ch4mpy/spring-addons/issues/155) Configurable HTTP status for responses to authorization_code flow initiation, authorization-code callback and logout. This makes BFF configuration easier for single page and mobile applications. Default OAuth2 response status (`302 Found`) can be overriden with:
```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        client:
          oauth2-redirections:
            pre-authorization-code: FOUND
            post-authorization-code: FOUND
            rp-initiated-logout: ACCEPTED
```
A per-request override can be done by setting `X-RESPONSE-STATUS` header with either a status code or label (for instance, both `201` and `ACCEPTED` are accepted as value).

### `7.1.14`
- update CSRF configuration for SPAs as instructed by spring-security team in https://github.com/spring-projects/spring-security/issues/14125 

### `7.1.13`
- [gh-153](https://github.com/ch4mpy/spring-addons/issues/153) have the default opaque tokens introspector accept `Integer`, `Long`, `Instant` and `Date` as value type for `iat` and `exp` claims

### `7.1.12`
- Spring boot `3.1.5` as transient dependency
- [gh-151](https://github.com/ch4mpy/spring-addons/issues/151) scan application context for `authenticationEntryPoint` and `accessDeniedHandler` to auto-configure resource servers (default returns `401` for unauthorized requests instead of `302 redirect to login`).

### `7.1.9`
- Spring boot `3.1.4` as transient dependency
- [gh-147](https://github.com/ch4mpy/spring-addons/issues/147) prevent addons test security conf to be auto-configured (complicates integration testing with test containers)

### `7.1.8`
- Fix servlet resource server with introspection auto-configuration

### `7.1.7`
- Enable to configure post-login and post-logout host (defaulted to client URI for backward compatibility)

### `7.1.5`
- Spring Boot 3.1.3

### `7.1.4`
- [gh-144](https://github.com/ch4mpy/spring-addons/issues/144) remove useless dependency on spring-session.

### `7.1.1`
- Remove Back-Channel Logout experimental support. Follow the [PR on Spring Security](https://github.com/spring-projects/spring-security/pull/12570) for official support.
- Multi-tenancy support on OAuth2 clients is now optional and disabled by default. Set `com.c4-soft.springaddons.oidc.client.multi-tenancy-enabled=true` to keep it activated.
- [gh-140](https://github.com/ch4mpy/spring-addons/issues/140): use AOP instead of custom authorized-client repositories to support multi-tenancy on OAuth2 clients. That way, any configured authorized-client repository is instrumented (no need to proxy or extend spring-addons one).

### `7.0.8`
- client `SecurityFilterChain` with `LOWEST_PRIORITY - 1` (instead of `HIGHEST_PRIORITY + 1`)
- `WWW_Authenticate` header with `Bearer` value for resource servers unauthorized requests (instead of `Basic`)

### `7.0.7`
- Spring Boot 3.1.2
- force usage of `AntPathRequestMatcher` when defining `permit-all` in servlet implementations because of https://spring.io/security/cve-2023-34035 (Spring `6.1.2`)

### `7.0.6`
- Fix a confusion between user subject and principal name in `SpringAddons(Server)OAuth2AuthorizedClientRepository` which could cause an authorized client not to be found when using another claim than subject as principal name.

### `7.0.3`
- Fix the condition to add a filter inserting CSRF protection cookie to responses

### `7.0.0`
See the [migration guide](https://github.com/ch4mpy/spring-addons/blob/master/7.0.0-migration-guide.md)
- merge all 6 starters into a single one
- reduce test libs count to 2: one with just annotations and another to ease testing of apps using the starter


## `6.x` Branch

### `6.2.3`
- Spring Boot 3.1.3

### `6.2.2`
- force usage of `AntPathRequestMatcher` when defining `permit-all` in servlet implementations because of https://spring.io/security/cve-2023-34035 (Spring `6.1.2`)

### `6.2.1`
- Spring Boot 3.1.2
- Fix a confusion between user subject and principal name in `SpringAddons(Server)OAuth2AuthorizedClientRepository` which could cause an authorized client not to be found when using another claim than subject as principal name.

### `6.2.0`
- remove `OAuth2AuthenticationFactory`: instead, use `Converter<Jwt, ? extends AbstractAuthenticationToken>`, `Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>>`, `OpaqueTokenAuthenticationConverter` or `ReactiveOpaqueTokenAuthenticationConverter`
- create `@WithJwt` to build OAuth2 `Authentication` during tests, using a JSON string or file on the classpath and submitting it to the JWT authentication converter. All samples and tutorials are updated with this new annotation.
- deprecate `@WithMockJwt` and `@OpenId` (use the new `@WithJwt` instead)
- remove the archetypes

### `6.1.16`
- [gh-133](https://github.com/ch4mpy/spring-addons/issues/133) Add a property to auto-configure an `audience` JWT validator (if present, the `aud` claim in the token will be checked to contain the URI provided in the conf)

### `6.1.15`
- [gh-129](https://github.com/ch4mpy/spring-addons/issues/129) Auto-configure (with application properties) additional parameters for authorization-code request. This allows, for instance, to send an `audience` as required by Auth0. Additional parameters are defined for each client registration. In the following sample, `client-registration` `a` and `b` references an existing entries in spring.security.oauth2.client.registration:
```yaml
com:
  c4-soft:
    springaddons:
      security:
        client:
          authorization-request-params:
            client-registration-a:
            - name: audience
              value: demo.c4-soft.com
            client-registration-b:
            - name: kc_idp_hint
              value: google
            - name: machin
              value: chose
```

### `6.1.14`
- [gh-128](https://github.com/ch4mpy/spring-addons/issues/128) add `@ClasspathClaims` to load claims from a JSON file in the classpath (test resources for instance).
```java
@Test
@WithMockJwtAuth(
  authorities = "ROLE_AUTHORIZED_PERSONNEL",
  claims = @OpenIdClaims(
    usernameClaim = "$['https://c4-soft.com/user']['name']",
    jsonFile = @ClasspathClaims("ch4mp.json")))
void givenUserIsAuthenticatedWithJsonClaims_whenGetClaims_thenOk() throws Exception {
  api.get("/greet").andExpect(status().isOk()).andExpect(content().string("Hello Ch4mp! You are granted with [ROLE_AUTHORIZED_PERSONNEL]."));
}
```
- [gh-127](https://github.com/ch4mpy/spring-addons/issues/127) add a `json` property to @OpenIdClaims to define all claims with a JSON string
```java
@WithMockJwtAuth(
authorities = { "ROLE_AUTHORIZED_PERSONNEL" },
claims = @OpenIdClaims(
  usernameClaim = "$['https://c4-soft.com/user']['name']",
  json = """
{
  "https://c4-soft.com/user": {
    "name": "Ch4mp",
    "email": "ch4mp@c4-soft.com"
  },
  "aud": "https://localhost:7082"
}"""))
```

### `6.1.13`
- [gh-125](https://github.com/ch4mpy/spring-addons/issues/125) Split claims used as `GrantedAuthority` source on comma and space (for instance, `scope` claim is usually a single string with comma separated scopes).

### `6.1.12`
- [gh-122](https://github.com/ch4mpy/spring-addons/issues/122) Support for parametrized OAuth2 Authentications in `@ParameterizedTest`. In the following sample, **mind the `@JwtAuthenticationSource`** (decoring test) **and `@ParameterizedJwtAuth`** (decoring test method parameter). The first annotation defines the different authentication instances, the second inserts the one for the current test in the security context and provides it as test method parameter:
```java
@ParameterizedTest
@JwtAuthenticationSource({ @WithMockJwtAuth("NICE"), @WithMockJwtAuth("VERY_NICE") })
void givenUserIsGrantedWithAnyNiceAuthority_whenGetRestricted_thenOk(@ParameterizedJwtAuth JwtAuthenticationToken auth) throws Exception {
	api.perform(get("/restricted"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.body").value("You are so nice!"));
}
```
  The above will run two distinct tests in  sequence, one with each of the provided `@WithMockJwtAuth`. Same for:
  * `@WithMockBearerTokenAuthentication` with `@BearerAuthenticationSource` and `@ParameterizedBearerAuth`
  * `@OpenId` with `@OpenIdAuthenticationSource` and `@ParameterizedOpenId`
  * `@WithOAuth2Login` with `@OAuth2LoginAuthenticationSource` and `@ParameterizedOAuth2Login`
  * `@WithOidcLogin` with `@OidcLoginAuthenticationSource` and `@ParameterizedOidcLogin`

### `6.1.11`
- Spring Boot 3.1.0

### `6.1.10`
- Spring Boot 3.0.7

### `6.1.9`
- [gh-112](https://github.com/ch4mpy/spring-addons/issues/112) fix CSRF token exposed to Javascript in servlets applications. Thanks to @giovannicandido for spotting and fixing this.

### `6.1.8`
- Spring Boot 3.0.6

### `6.1.7`
- create `ServletConfigurationSupport` and `ReactiveConfigurationSupport` in `spring-addons-{webmvc|webflux}-core` to remove code duplication from starters

### `6.1.5`
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
                name = "https://c4-soft.com/user",
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

### `6.1.4`
- gh-106: Properties to disable spring-addons security filter-chain auto-configuration:
  * for clients: empty path-matchers array or `com.c4-soft.springaddons.security.client.enabled=false`
  * for resource servers: `com.c4-soft.springaddons.security.enabled=false`

### `6.1.3`
- fix CSRF protection configuration (apply https://docs.spring.io/spring-security/reference/5.8/migration/servlet/exploits.html#_i_am_using_a_single_page_application_with_cookiecsrftokenrepository and https://docs.spring.io/spring-security/reference/5.8/migration/reactive.html#_i_am_using_angularjs_or_another_javascript_framework)
- rework the Javadoc and README of all 6 OAuth2 starters
- introduce a Back-Channel Logout client implementation to both client starters
- rework BFF and resource server & client tutorials with spring-addons client starters

### `6.1.2`
- boot 3.0.4
- add a BFF tutorial

### `6.1.1`
- add [spring-addons-webmvc-client](https://github.com/ch4mpy/spring-addons/tree/master/webmvc/spring-addons-webmvc-client)
- add [spring-addons-webflux-client](https://github.com/ch4mpy/spring-addons/tree/master/webflux/spring-addons-webflux-client)
- in both client starters, add a logout handler for OP with RP-Initiated logout implementations which do not comply with OIDC standard. This handler is configurable from properties (logout end-point and post-logout URIs). See [`resource-server_with_ui` tutorial](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials/resource-server_with_ui) for details.

### `6.1.0`
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

### `6.0.16`
- Add a `username-clame` configuration property to define, per issuer, from which claim of the access token should be retrieved the username (what is returned by `Authentication::getName`). Default is subject for backward compatibility

### `6.0.15`
- [gh-100](https://github.com/ch4mpy/spring-addons/issues/100) prevent a NPE in reactive resource-server using JWT spring-addons starter when the issuer in an access token is not listed in conf. All credits go to [lArtiquel](https://github.com/lArtiquel) who spotted the bug and submitted the fix.

### `6.0.13`
- create `ServerHttpRequestSupport` and `HttpServletRequestSupport` to help statically access to the request in current context (usage in authentication converters for instance

### `6.0.12`
- add `@WithOAuth2Login` and `@WithOidcLogin` to populate test security-context with an `OAuth2AuthenticationToken` instance (with respectively `DefaultOAuth2User` and `DefaultOidcUser` as principal)
- bump to spring-boot `3.0.2`
- default authorities collection in tests annotations, `MockMvc` post-processors and `WebTestClient` mutators is set to empty array (instead of `{ "ROLE_USER" }`)

### `6.0.11`
- [gh-86](https://github.com/ch4mpy/spring-addons/issues/86) `OAuthentication::setDetails` [should not throw](https://github.com/spring-projects/spring-security/issues/11822) until spring-security 6.1 is released
- [gh-87](https://github.com/ch4mpy/spring-addons/issues/87) spring-addons JWT starters should start even if `spring.security.oauth2.resourceserver.jwt.issuer-uri` is set in configuration properties

### `6.0.10`
- [gh-83](https://github.com/ch4mpy/spring-addons/issues/83) do not force traffic to http when SSL is not enabled (just force https when SSL is enabled)

### `6.0.9`
- Make OAuthentication immutable

### `6.0.7`
- release with spring-boot 3.0.0 GA as transitive dependency

### `6.0.1`
- [samples](https://github.com/ch4mpy/spring-addons/tree/master/samples) for all combinations of:
  * webmvc / webflux
  * JWT decoder / access token introspection
  * `OAuthentication<OpenidClaimSet>` / Spring default `Authentication` implementation (`JwtAuthenticationToken` for JWT decoder or `BearerTokenAuthentication` for token introspection)
- minor fixes (@WithMockAuthentication and reactive + introspection starter)

### `6.0.0`
- Switch to spring-boot 3 (and spring-security 6)
- Stop supporting the [very deprecated Keycloak libs for spring](https://github.com/keycloak/keycloak/discussions/10187)

## `5.x` branch
This branch is not maintained anymore. Only versions compatible with Spring 6.1.x (Boot 3.1.x) and JDK >= 17 are maintained.

### `5.4.2`
- [gh-100](https://github.com/ch4mpy/spring-addons/issues/100) prevent a NPE in reactive resource-server using JWT spring-addons starter when the issuer in an access token is not listed in conf. All credits go to [lArtiquel](https://github.com/lArtiquel) who spotted the bug and submitted the fix.

### `5.4.0`
- Use a single bean name for
  * `ServletSecurityBeans` and `ReactiveSecurityBeans`: AddonsSecurityBeans
  * `@AutoConfigureAddonsSecurity{Webmvc|Weblux}{Jwt|Introspecting}`: `@AutoConfigureAddonsSecurity`
- Add `@AutoConfigureAddonsWebSecurity` to do the same as existing `@AutoConfigureAddonsSecurity` which now loads authorities converter only (useful to unit-test @Components that are not @Controller).
- More options for CSRF configuration (enum property instead of a boolean) and CSRF disabled by default when session-management is state-less.
- Compatibility with JDK 1.8 and spring-boot 2.6 (get version 6.x for spring-boot 3 and JDK 17)
- webflux dependencies cleanup (were pulling some servlet dependencies)
- All samples now demo @Service and @Repository unit-tests in addition to @Controller ones.

### `5.3.0`
Use `JwtAuthenticationToken` or `BearerAuthenticationToken` by default in  resource-server starters. For some reason, `OAuthentication<OpenidClaimSet>` frightens rookies.
- make `OAuth2AuthenticationFactory` `@Bean` optional.
- remove `OAuth2ClaimsConverter` (interface definition and @ConditionalOnMissingBean)
- remove the recently added `oauth2-authentication-factory-enabled` property (instead, evaluate if an `OAuth2AuthenticationFactory` bean was provided)

### `5.2.2`
- resource-server starter main beans (`Security(Web)FilterChain`) are no-longer "conditional on missing": if you dan't want it, don't pull starter lib.
- add `oauth2-authentication-factory-enabled` flag to easily fall-back to Spring default OAuth2 `Authentication` implementations (`JwtAuthenticationToken` and `BearerTokenAuthentication` for resource-servers with respectively JWT decoder or opaque token introspection)

### `5.1.3`
- keycloak 19
- release with JDK 17 and boot 2.7.2
- release with JDK 1.8 and boot 2.6.10

### `5.1.0`
- Support token introspection for resource-servers.
- Rename `spring-addons-*-jwt-resource-server-test` to `spring-addons-*-test` as it apply for both JWT and introspection

### `5.0.0`
Rename modules to:
- have all module names start with `spring-addons` prefix, then intermediate module if any (`archetypes`, `samples`, `starters`, `webmvc` or `webflux`) and last what leaf module aims at
- better reflect what it does

For instance, `spring-security-oauth2-webmvc-addons` only applies to resource-servers secured with JWTs (not to opaque tokens) -> renamed to `spring-addons-webmvc-jwt-resource-server`

Rename `com.c4-soft.springaddons.security.token-issuers` configuration properties to `com.c4-soft.springaddons.security.issuers` for the same reason: only accepts JWT token issuers (and not opaque token issuers with introspection end-point for instance)

### `4.5.0`
CSRF enabled by default, using `CookieCsrfTokenRepository` if session management is "stateless".

### `4.4.4`
[gh-53 GenericMethodSecurityExpressionHandler should accept expression root suppliers for many authentication type](https://github.com/ch4mpy/spring-addons/issues/53)

### `4.4.2`
add [reCAPTCHA validation spring-boot starter](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-starters-recaptcha)

### `4.4.1`
rename `@WithMockOidcAuth` to shorter and more expressive `@OpenId`: it populates test security context with an OAuth2 `Àuthentication` containing an OpenID claim-set

### `4.4.0`
- rename `OpenidClaimSet` to `OpenidClaimSet`: more expressive as this class contains OpenID token claims only
- rename `OAuthentication` to `OAuthentication`: it has no more adherence to OpenID (just specific to authentication with encoded claims in a bearer string)

### `4.3.2`
Slight properties rework. Now, to configure issuers and authorities mapping:

```properties
# should be set to where your authorization-server is
com.c4-soft.springaddons.security.issuers[0].location=https://localhost:8443/realms/master

# should be configured with a list of private-claims this authorization-server puts user roles into
# below is default Keycloak conf for a `spring-addons` client with client roles mapper enabled
com.c4-soft.springaddons.security.issuers[0].authorities.claims=realm_access.roles,resource_access.spring-addons-public.roles,resource_access.spring-addons-confidential.roles

# use IDE auto-completion or see SpringAddonsSecurityProperties javadoc for complete configuration properties list
```
where `caze` is one of `unchanged`, `upper` or `lower`

### `4.3.0`
- [gh-50](https://github.com/ch4mpy/spring-addons/issues/50): One entry per authorization-server for authorities mapping (see samples `application.properties` files for new configuration structure).
- [gh-51](https://github.com/ch4mpy/spring-addons/issues/51): Group archetypes, webmvc and webflux modules.

### `4.2.1`
- [gh-49](https://github.com/ch4mpy/spring-addons/issues/49): Samples in dedicated modules. All samples are moved from libs tests to [`samples`](https://github.com/ch4mpy/spring-addons/tree/master/samples) module, with one sub-module per sample.

### `4.2.0`
Cleanup and prepare for spring-boot 3:
- [gh-46](https://github.com/ch4mpy/spring-addons/issues/46): split webmvc & webflux content from `spring-addons-oauth2` 
- [gh-47](https://github.com/ch4mpy/spring-addons/issues/47): provide `SecurityFilterChain` bean instead of extending `WebSecurityConfigurerAdapter`
- [gh-48](https://github.com/ch4mpy/spring-addons/issues/48): make use of spring-boot `@AutoConfiguration`

### `4.1.5`
- Replace multiple JWT issuers JwtDecoder (from 4.1.4) with `AuthenticationManagerResolver` @Beans 

### `4.1.4`
- JwtDecoder for configuring multiple JWT issuers (single resource server accepting IDs from two or more authorization-servers)

### `4.1.3`
- finer configuration control with `SpringAddonsSecurityProperties`

### `4.0.0`
- move keycloak related code to `spring-addons-keycloak`

### `3.2.0`
- Master branch back to single JDK: 17
- Create `jdk1.8` and `jdk11` branches

### `3.1.16`
- Add [spring-addons-archetypes-webmvc-multimodule](https://github.com/ch4mpy/spring-addons/blob/master/spring-addons-archetypes-webmvc-multimodule) to boostrap native-ready Spring REST API with webmvc, JPA, OpenAPI and OpenID security.

### `3.1.13`
- Add a [sample](https://github.com/ch4mpy/spring-addons/blob/master/custom-oidc-authentication-impl.MD) with `OpenidClaimSet` specialisation (parse private claims in addition to authorities).

### `3.1.12`
- Improve `OidcReactiveApiSecurityConfig` and `OidcServletApiSecurityConfig` usability: ease security beans replacement (including authorities and authentication converter for use cases where OAuthentication is not enough)

### `3.1.11`
- Rename `SecurityProperties` to less conflicting `SpringAddonsSecurityProperties`

### `3.1.10`
- Turn `AbstractOidc...ApiSecurityConfig` into `Oidc...ApiSecurityConfig` with default authorities mapper being keycloak or Auth0 depending on `com.c4-soft.springaddons.security.keycloak.client-id` being set or not
- More CORS and authorities mapping configuration in `SecurityProperties`

### `3.1.8`
- Fix missing JTI claim mapping from `@OpenIdClaims` ([gh-35](https://github.com/ch4mpy/spring-addons/issues/35)).

### `3.1.7`
- Add `AbstractOidcReactiveApiSecurityConfig` to `spring-addons-oauth2`. It provides with reasonable default WebSecurityConfig for a reactive (weblux) based API secured with OAuthentication.

### `3.1.6`
- Add `AbstractOidcServletApiSecurityConfig` to `spring-addons-oauth2`. It provides with reasonable default WebSecurityConfig for a servlet based API secured with OAuthentication.

### `3.1.4`
- lombok with provided scope ([gh-31](https://github.com/ch4mpy/spring-addons/issues/31))

### `3.1.3`
- spring-boot 2.6.1
- release with JDK version (compilation and runtime target)

### `3.1.0`
- spring-boot 2.6

### `3.0.0`
- in OAuth2 related test annotations all claims are now grouped under a single `claims = @OpenIdClaims(...)`
- `@WithMockJwtAuth` in addition to `@WithMockKeycloakAuth` and `@WithMockOidcAuth`
- some code cleanup, quite a bunch of code removed and some renaming (including breaking changes, reason for new major version)

### `2.6.6`
- import spring-boot 2.5.5 BOM (instead of inheriting 2.5.4 POM)

### `2.6.5`
- Downgrade Java compatibility to 1.8

### `2.6.1`
- spring-boot 2.5.4

### `2.6.0`
- replace `KeycloakOidcIdAuthenticationConverter` with `SynchronizedJwt2OidcIdAuthenticationConverter` and complement it with `ReactiveJwt2OidcIdAuthenticationConverter`
- remove references to Keycloak from `spring-addons-oauth2` (implementations where mostly useless)

### `2.5.4`
- bump Keycloak BOM to 14.0.0

### `2.5.3`
- bump spring-boot to 2.5

### `2.5.1`
- introduce `@JsonObjectClaim` and `@JsonArrayClaim` to configure complex private claims. Sample: `@WithMockKeycloakAuth(otherClaims = @ClaimSet(jsonObjectClaims = @JsonObjectClaim(name = "foo", value = "{\"bar\":\"bad\", \"nested\":{\"deep\":\"her\"}, \"arr\":[1,2,3]}")))` or `@WithMockOidcId(privateClaims = @JsonObjectClaim(name = "foo", value = "{\"bar\":\"bad\", \"nested\":{\"deep\":\"her\"}, \"arr\":[1,2,3]}"))`

### `2.4.1`
- [issue #14](https://github.com/ch4mpy/spring-addons/issues/14) added jti and nbf (from JWT spec) to @IdTokenClaims (an ID token is a JWT)
- [issue #14](https://github.com/ch4mpy/spring-addons/issues/14) added session_state to @IdTokenClaims as per https://openid.net/specs/openid-connect-session-1_0.html#CreatingUpdatingSessions
- [issue #14](https://github.com/ch4mpy/spring-addons/issues/14) rename `privateClaims` to `otherClaims` in `@WithMockKeycloakAuth`
- [issue #15](https://github.com/ch4mpy/spring-addons/issues/15) `GrantedAuthoritiesMapper` is now optional in test config. Defaulted to `NullAuthoritiesMapper`

### `2.4.0`
- rename `ServletKeycloakAuthUnitTestingSupport::keycloakAuthenticationToken()` to `authentication()` to improve API fluidity (`api.with(keycloak.authentication()).get(...)`)

### `2.3.0`
- implementation closer to [open ID specs](https://openid.net/specs/openid-connect-core-1_0.html): split claims into `@IdTokenClaims` and `@OidcStandardClaims`
- re-use OIDC ID annotations into `@WithMockKeycloakAuth`

### `2.2.0`
- `OidcId::getName()` returns `subject` claim instead of `preferred_username`
- replace `name` with `subject` in `@WithMockOidcId`
- replace `name` from `@WithMockKeycloakAuth` with `preferedUsername` in `@WithAccessToken`
- support for private claims in `@WithMockOidcId` and `@WithMockKeycloakAuth` (claims with values of type `int`, `long`, `String` and `String[]` only)
- add missing subject claim in Keycloak access and ID tokens
- compose `@WithAccessToken` with `@WithKeycloakIDToken` instead of repeating properties (`AccessToken` extends `IDToken`)
- add advanced `@WithMockKeycloakAuth` sample usage in [`spring-addons-oauth2-test` README](https://github.com/ch4mpy/spring-addons/tree/master/spring-addons-oauth2-test)

### `2.1.0`
- fix Keycloak typo (was wrongly spelled Keycloack at many places)
- add samples with authorities retrieved from a DB instead of the JWT for both OAuthentication and JwtAuthenticationToken
- add sample involving `keycloak-spring-boot-starter` and `keycloak-spring-security-adapter`

### `2.0.0`
This release is still focused on unit-testing Spring OAuth2 applications

- `@WithMockAuthentication` annotation along with `mockAuthentication()` servlet (webmvc) and reactive (webflux) flow APIs. You choose the `Authentication` type, the framework feeds the security context with a Mockito mock. This is dead simple but should cover 99% of test cases. I wonder why I didn't think of it sooner...
- Focus solely on adding to Spring `Authentication` implementations and tests tooling (no more alternatives, with an exception for `OidcId` which overlaps Spring's `OidcIdToken`)
- Split `webmvc` (servlets) and `webflux` (reactive) code in distinct libs to ease dependency management
- Re-shuffle packages and jars (less code, less jars, more expressive package names)
- WIP: Extensives samples and tests. Samples are boot apps under `src/test` to keep jars small
- Use Keycloak as authorisation-server for all resource-server samples, each of which configuring a specific `Authentication` impl

Note that I chose Keycloak because it's a feature rich, easy to setup authorisation-server.
It should not be much of an effort to migrate sample resource-servers to another one, with an exception to those using `KeycloakAuthenticationToken` as authentication impl, of course.
