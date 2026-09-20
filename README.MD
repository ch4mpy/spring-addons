# spring-addons

**Spring Boot starters that turn OAuth2 / OpenID Connect configuration in Spring RESTful backends into a matter of properties, and OAuth2 access-control testing into a matter of annotations.**

[![Maven Central](https://img.shields.io/maven-central/v/com.c4-soft.springaddons/spring-addons-starter-oidc?label=Maven%20Central&color=blue)](https://central.sonatype.com/namespace/com.c4-soft.springaddons)
[![CI](https://github.com/ch4mpy/spring-addons/actions/workflows/ci.yml/badge.svg)](https://github.com/ch4mpy/spring-addons/actions/workflows/ci.yml)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.1-6DB33F?logo=springboot&logoColor=white)](#compatibility)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](./license.txt)
[![Documentation](https://img.shields.io/badge/documentation-ch4mpy.github.io-blue)](https://ch4mpy.github.io/spring-addons/)

Works with Keycloak, Auth0, Amazon Cognito, Microsoft Entra ID and any other OpenID Provider, with several of them at a time if needed. Servlet (WebMVC) and reactive (WebFlux) applications are both supported. These libs are a complement to the official `spring-boot-starter-oauth2-resource-server` and `spring-boot-starter-oauth2-client`, not a replacement.

## Quickstart

A REST API accepting access tokens issued by Keycloak, with roles mapped to Spring Security authorities, CORS, and public routes. There is no security Java configuration to write.

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
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
```

Set the `springaddons.version` property to the version displayed by the Maven Central badge above.

```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        # Trusted OpenID Providers. The "iss" claim of an access token selects the entry,
        # and with it the username and authorities mapping. Add as many as needed.
        ops:
          - iss: http://localhost:7080/auth/realms/spring-addons
            username-claim: preferred_username
            authorities:
              # JSON paths in the token payload: Keycloak realm roles and client roles here
              - path: $.realm_access.roles
              - path: $.resource_access.*.roles
        resourceserver:
          # Anything else requires a valid access token and is answered with a 401, not a
          # redirection to a login page
          permit-all:
            - /greetings/public
        cors:
          - path: /**
            allowed-origin-patterns: https://localhost:4200
```

Access control then lives where it belongs, next to the code it protects:

```java
@GetMapping("/greetings/me")
@PreAuthorize("hasAuthority('NICE')")
GreetingDto getGreeting(Authentication auth) { ... }
```

And the tests run that very same authorities mapping, without decoding a token and without an authorization server:

```java
@Test
@WithJwt("brice.json") // a JSON claim-set in test resources
void givenUserIsBrice_whenGetMe_thenOk() throws Exception {
    api.get("/greetings/me").andExpect(status().isOk());
}
```

`@WithJwt` builds the security context by running that claim-set through **the application's own authentication converter**, so the username, the authorities and the `Authentication` implementation are the ones the application would build at runtime. This is what `spring-security-test` request post-processors and mutators cannot do: they skip the converter and build a stub `Authentication` themselves.

From there, [the five runnable samples](https://github.com/ch4mpy/spring-addons/tree/master/samples) are the fastest way in. Start with [`resource-server`](https://github.com/ch4mpy/spring-addons/tree/master/samples/resource-server), it is the smallest.

## Compatibility

Each major line of spring-addons targets a major line of Spring Boot and is built against it.

| spring-addons | Spring Boot | Java | Notes |
|---|---|---|---|
| `9.x` | `4.1.x` (`4.0.x` up to `9.1.5`) | 17+ | Current line. `9.4.0` is built against Boot `4.1.1` and Spring Security `7.1.1`, the samples use Spring Cloud `2025.1.3`. |
| `8.x` | `3.4.x` to `3.5.x` | 17+ | Last release `8.1.25`, March 2026, built against Boot `3.5.11`. |
| `7.x` | `3.3.x` | 17+ | Last release `7.8.12`, November 2024. |

The exact version of the current line is the one in the Maven Central badge above. Changes are documented per version in the [release notes](https://github.com/ch4mpy/spring-addons/blob/master/release-notes.md), and breaking changes in the migration guides ([7.0.0](https://github.com/ch4mpy/spring-addons/blob/master/7.0.0-migration-guide.md), [8.0.0](https://github.com/ch4mpy/spring-addons/blob/master/migrate-to-8.0.0.md), [9.2.0](https://github.com/ch4mpy/spring-addons/blob/master/migrate-to-9.2.0.md)).

## Modules

| Module | What it is for |
|---|---|
| [`spring-addons-starter-oidc`](https://ch4mpy.github.io/spring-addons/oidc/) | Resource server and `oauth2Login` client security auto-configuration, driven by properties |
| [`spring-addons-starter-rest`](https://ch4mpy.github.io/spring-addons/rest/) | `RestClient` / `WebClient` / `@HttpExchange` beans auto-configured from properties: authorization, proxy, SSL, timeouts |
| [`spring-addons-oauth2-test`](https://ch4mpy.github.io/spring-addons/testing/annotations/) | Annotations populating the test security context with OAuth2 authentications, on any kind of `@Component` |
| [`spring-addons-starter-oidc-test`](https://ch4mpy.github.io/spring-addons/testing/slices/) | Test companion for applications using `spring-addons-starter-oidc` |
| [`spring-addons-starter-openapi`](https://ch4mpy.github.io/spring-addons/openapi/) | Makes the enum values in a springdoc-openapi spec match what the application really accepts and emits |
| [`spring-addons-starter-recaptcha`](https://ch4mpy.github.io/spring-addons/recaptcha/) | Server-side validation of Google reCAPTCHA v2 and v3 |

Each module is usable on its own. The complete reference is on the [documentation site](https://ch4mpy.github.io/spring-addons/), one page per concern.

## What would be hard to write yourself

Cutting configuration code is the visible part. The reasons to actually depend on these starters are the cases where the framework leaves us alone:

- **Several heterogeneous OpenID Providers at once**, static or resolved dynamically, each with its own username claim and its own authorities mapping. One more entry in `ops`, no code.
- **One `refresh_token` flow at a time per session.** Most authorization servers rotate refresh tokens. When a user-agent fires parallel requests with an expired access token in session, Spring Security runs one flow per request, only one succeeds, and the others are answered with a `401`. This was [declined upstream](https://github.com/spring-projects/spring-security/issues/15145) as something the framework cannot solve generally. `spring-addons-starter-oidc` decorates the authorized client provider so that the authorization server sees a single token request.
- **A complete BFF.** Authorization code with PKCE, RP-Initiated Logout including for the providers which do not strictly implement it (Auth0, Cognito), Back-Channel Logout, a CSRF cookie readable by JavaScript, and `2xx` statuses instead of `3xx` so that a single-page application can follow the redirections itself.
- **REST clients that survive real networks.** HTTP proxies from `HTTP_PROXY` and `NO_PROXY` including proxy credentials on HTTPS tunnels, SSL bundles, self-signed certificates, timeouts, and switching the underlying HTTP client library, all from properties.
- **Tests that exercise the real mapping**, as shown in the quickstart above, on `@Service` and `@Repository` too, not only on controllers.

We keep complete control over what is auto-configured. Almost every auto-configured component is `@ConditionalOnMissingBean`, so spring-addons backs off as soon as the application defines its own bean, and overriding a default means defining that one bean, not a whole `Security(Web)FilterChain`. The auto-configured filter chains have the lowest precedence, so an application can add its own chains with stricter security matchers. The [risks and mitigations](https://ch4mpy.github.io/spring-addons/oidc/risks/) page is worth two minutes before adopting, and [what you would write without spring-addons](https://ch4mpy.github.io/spring-addons/without-spring-addons/) names the hand-written Spring Security equivalent of every auto-configured bean.

## `spring-addons-starter-oidc`

Auto-configuration for resource servers:
- accepting tokens issued by several trusted authorization servers
- mapping authorities from a variety of claims, including nested ones, with custom prefix and case
- CORS configuration
- allowing anonymous preflight requests using the path-matchers in CORS configuration

Auto-configuration for clients with `oauth2Login`:
- customizing the responses returned to the frontend during the authorization code and RP-Initiated Logout flows. The URI in the `Location` header can be defined in properties and overridden by the frontend with headers or query parameters, and the HTTP status can be moved to the `2xx` range so that the frontend observes the response and handles the redirection in JavaScript instead of letting the browser follow with a cross-origin Ajax request.
- exposing the CSRF token as a cookie accessible to a single-page application
- logging out from authorization servers which do not strictly implement RP-Initiated Logout, Auth0 and Amazon Cognito for instance
- activating and configuring Back-Channel Logout
- adding extra parameters to authorization and token requests, like the `audience` required by Auth0 or Keycloak's `kc_idp_hint`
- CORS configuration, and anonymous preflight requests

The reference pages for [resource servers](https://ch4mpy.github.io/spring-addons/oidc/resource-server/) and [clients](https://ch4mpy.github.io/spring-addons/oidc/client/) document every property, with an FAQ covering Auth0 audiences, Keycloak dynamic realms, Microsoft Entra ID caveats, proxies in front of the token endpoint, and cookies.

## `spring-addons-starter-rest`

At an age where OpenAPI specs are generated from REST API source code, and client code generated from those specs, what is left to do for inter-service calls is configuring the clients: `Basic` or `Bearer` authorization, HTTP proxies, timeouts, SSL bundles, and the choice of the underlying HTTP client library. All of it is verbose and error-prone in Java, and all of it is a few properties here:

```yaml
com:
  c4-soft:
    springaddons:
      rest:
        client:
          # Exposes a RestClient bean named machinClient (or a WebClient in a reactive app)
          machin-client:
            base-url: ${machin-api}
            authorization:
              oauth2:
                # Authorize outgoing requests with the Bearer token in the security context
                forward-bearer: true
          bidule-client:
            base-url: ${bidule-api}
            # Expose the builder instead of an already built client, to fine tune it
            expose-builder: true
            authorization:
              oauth2:
                # Authorize outgoing requests with a token obtained from a client registration
                oauth2-registration-id: bidule-registration
```

These beans can be auto-wired in any `@Component` or used to back `@HttpExchange` proxies. An HTTP Service group can be backed by an auto-configured client, so that the generated proxies share its base URL, headers, authorization, and request factory:

```java
@Configuration
@ImportHttpServices(group = "keycloak-group", types = {UsersApi.class, ClientRoleMappingsApi.class})
class HttpServicesConfiguration {
}
```

```yaml
com:
  c4-soft:
    springaddons:
      rest:
        client:
          keycloak-client:
            base-url: https://${cn}:3643/auth
            ssl-bundle: self-signed
            headers:
              Accept:
                - application/json
                - application/problem+json
            authorization:
              oauth2:
                oauth2-registration-id: rest-api
        group:
          keycloak-group:
            client: keycloak-client
```

Proxy configuration is applied by default as soon as the `HTTP_PROXY` and `NO_PROXY` environment variables are set, and can be overridden or disabled with properties. This starter is usable on its own, including in non-web applications. See the [reference](https://ch4mpy.github.io/spring-addons/rest/) for the bean naming rules and the advanced options.

## Testing access control

Testing access control requires a security context populated with a fine-tuned `Authentication`. `spring-security-test` provides `MockMvc` request post-processors and `WebTestClient` mutators, but they work only in the context of a request, which limits them to controllers. To test any kind of `@Component`, including `@Service` and `@Repository`, the options are to build the security context by hand, or to let annotations do it.

The notable difference with `spring-security-test` is the one mentioned in the quickstart: the authentication converter defined in the security configuration is ignored by the post-processors and mutators. Building the security context in a resource server with a JWT decoder has three steps:

1. the Bearer string is decoded, validated, and turned into a `org.springframework.security.oauth2.jwt.Jwt` by a `JwtDecoder`
2. that `Jwt` is turned into an `AbstractAuthenticationToken` by an authentication converter, which is where claims become authorities and where a custom `Authentication` implementation is chosen
3. the `Authentication` is put in the security context

`@WithJwt` mocks step 1 only: it builds a stub `Jwt` from a JSON payload in test resources and hands it to the authentication converter. The `.jwt()` post-processor jumps to step 3 and builds the `Authentication` itself, so the conversion logic is never exercised. Note that this requires the authentication converter to be exposed as a `@Bean` rather than inlined as a lambda in the filter chain definition, which `spring-addons-starter-oidc` does out of the box.

Reference: [the annotations](https://ch4mpy.github.io/spring-addons/testing/annotations/), [the test slices](https://ch4mpy.github.io/spring-addons/testing/slices/), and [this Baeldung article](https://www.baeldung.com/spring-oauth-testing-access-control).

## Documentation and tutorials

A few weeks of trial and error can save fifteen minutes of reading a page. The [documentation site](https://ch4mpy.github.io/spring-addons/) is the complete reference, the samples are runnable, and three tutorials from this repo now live on Baeldung:

- [Getting started with Keycloak and Spring Boot](https://www.baeldung.com/spring-boot-keycloak)
- [Creating an OAuth2 BFF with `spring-cloud-gateway` and consuming it from a single-page application](https://www.baeldung.com/spring-cloud-gateway-bff-oauth2)
- [Testing access control with mocked OAuth2 authentications](https://www.baeldung.com/spring-oauth-testing-access-control)

Also useful: the [runnable samples](https://github.com/ch4mpy/spring-addons/tree/master/samples), the [release notes](https://github.com/ch4mpy/spring-addons/blob/master/release-notes.md), [`llms.txt`](https://github.com/ch4mpy/spring-addons/blob/master/llms.txt) when a coding assistant is involved, [contributing](https://github.com/ch4mpy/spring-addons/blob/master/CONTRIBUTING.md), and the [Maven Central reminders](https://github.com/ch4mpy/spring-addons/blob/master/maven-central.md) for maintainers.
