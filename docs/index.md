---
title: Home
nav_order: 1
description: "Spring Boot starters giving a Spring backend for single-page and mobile applications the OAuth2 / OpenID Connect behaviours Spring Security does not default to, as properties, plus access-control tests running the real authorities mapping. Keycloak, Auth0, Amazon Cognito, Microsoft Entra ID, WebMVC and WebFlux."
permalink: /
---

# spring-addons
{: .no_toc }

**Spring Security's OAuth2 defaults were written for server-rendered applications. These Spring Boot starters give a Spring backend for single-page and mobile applications the OAuth2 / OpenID Connect behaviours it actually needs, as properties, and access-control tests that run the real authorities mapping.**

[![Maven Central](https://img.shields.io/maven-central/v/com.c4-soft.springaddons/spring-addons-starter-oidc?label=Maven%20Central&color=blue)](https://central.sonatype.com/namespace/com.c4-soft.springaddons)
[![CI](https://github.com/ch4mpy/spring-addons/actions/workflows/ci.yml/badge.svg)](https://github.com/ch4mpy/spring-addons/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](https://github.com/ch4mpy/spring-addons/blob/master/license.txt)

Works with Keycloak, Auth0, Amazon Cognito, Microsoft Entra ID and any other OpenID Provider, with several of them at a time if needed. Servlet (WebMVC) and reactive (WebFlux) applications are both supported. These libs are a complement to the official `spring-boot-starter-oauth2-resource-server` and `spring-boot-starter-oauth2-client`, not a replacement: they add the beans those starters leave to the application.

## Why not just the official starters

Fewer lines of configuration is the visible part, not the reason. A backend consumed by JavaScript or by a mobile app hits Spring Security defaults which were designed for a browser doing navigations, and none of them fails at startup:

| What is observed | Why | With `spring-addons-starter-oidc` |
|---|---|---|
| `hasRole('ADMIN')` never matches, even for an admin | Authorities come from the `scope` claim only. Keycloak, Auth0 and Cognito put roles elsewhere | `authorities[].path`, a JSON path in the claims |
| Every call fails with a CORS error on the preflight | CORS configured on the MVC side runs after the security filters, which reject an `OPTIONS` without credentials | `cors[]` on the security chain |
| A `fetch` starting the login flow dies with an opaque CORS error | `302` to the authorization server, which the browser follows cross-origin inside the `fetch` | `2xx` with the `Location` header, the JavaScript navigates itself |
| An API call without a session gets a login page instead of a `401` | The entry point redirects, as it should for a navigation | `authentication-entry-point: UNAUTHORIZED` |
| Every `POST` from the frontend is `403`, so CSRF gets disabled | The CSRF token lives in the session, JavaScript cannot read it | `csrf: cookie-accessible-from-js` |
| The frontend chooses where to land after login, and the BFF follows blindly | That destination is application code, and unvalidated it is an open redirect | Validated against `post-login-allowed-uri-patterns` |
| Users are logged out at random under load | One `refresh_token` flow per parallel request, and rotated tokens invalidate the others. [Declined upstream](https://github.com/spring-projects/spring-security/issues/15145) | One token request per session at a time |
| Tests pass with authorities production never grants | `spring-security-test` builds the `Authentication` itself and skips the application's converter | `@WithJwt` runs the real converter, on any `@Component` |

The complete list, with what each item is (a security flaw, a broken behaviour, or a test that lies) and the honest boundary of the claim, is on [what goes wrong without it]({{ site.baseurl }}/what-goes-wrong/). The starter keeps Spring's defaults unless a property says otherwise, and the [`bff` sample](https://github.com/ch4mpy/spring-addons/tree/master/samples/bff) sets all of them.

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

`@WithJwt` builds the security context by running that claim-set through **the authentication converter of the application itself**, so the username, the authorities and the `Authentication` implementation are the ones the application would build at runtime. This is what `spring-security-test` request post-processors and mutators cannot do: they skip the converter and build a stub `Authentication` themselves.

From there, [the five runnable samples]({{ site.baseurl }}/samples/) are the fastest way in. Start with `resource-server`, it is the smallest.

## Modules

| Module | What it is for |
|---|---|
| [`spring-addons-starter-oidc`]({{ site.baseurl }}/oidc/) | Resource server and `oauth2Login` client security auto-configuration, driven by properties |
| [`spring-addons-starter-rest`]({{ site.baseurl }}/rest/) | `RestClient` / `WebClient` / `@HttpExchange` beans auto-configured from properties: authorization, proxy, SSL, timeouts |
| [`spring-addons-oauth2-test`]({{ site.baseurl }}/testing/annotations/) | Annotations populating the test security context with OAuth2 authentications, on any kind of `@Component` |
| [`spring-addons-starter-oidc-test`]({{ site.baseurl }}/testing/slices/) | Test companion for applications using `spring-addons-starter-oidc` |
| [`spring-addons-starter-openapi`]({{ site.baseurl }}/openapi/) | Makes the enum values in a springdoc-openapi spec match what the application really accepts and emits |
| [`spring-addons-starter-recaptcha`]({{ site.baseurl }}/recaptcha/) | Server-side validation of Google reCAPTCHA v2 and v3 |

Each module is usable on its own.

## What would be hard to write yourself

Cutting configuration code is the visible part. The reasons to actually depend on these starters are the cases where the framework leaves us alone:

- **Several heterogeneous OpenID Providers at once**, static or resolved dynamically, each with its own username claim and its own authorities mapping. One more entry in `ops`, no code.
- **One `refresh_token` flow at a time per session.** Most authorization servers rotate refresh tokens. When a user-agent fires parallel requests with an expired access token in session, Spring Security runs one flow per request, only one succeeds, and the others are answered with a `401`. This was [declined upstream](https://github.com/spring-projects/spring-security/issues/15145) as something the framework cannot solve generally. `spring-addons-starter-oidc` decorates the authorized client provider so that the authorization server sees a single token request.
- **A complete BFF.** Authorization code with PKCE, RP-Initiated Logout including for the providers which do not strictly implement it (Auth0, Cognito), Back-Channel Logout, a CSRF cookie readable by JavaScript, and `2xx` statuses instead of `3xx` so that a single-page application can follow the redirections itself.
- **REST clients that survive real networks.** HTTP proxies from `HTTP_PROXY` and `NO_PROXY` including proxy credentials on HTTPS tunnels, SSL bundles, self-signed certificates, timeouts, and switching the underlying HTTP client library, all from properties.
- **Tests that exercise the real mapping**, as shown in the quickstart above, on `@Service` and `@Repository` too, not only on controllers.

The page which spells this out bean by bean, with the hand-written Spring Security equivalent of each one, is [what you would write without spring-addons]({{ site.baseurl }}/without-spring-addons/).

The two items which come up most often have a write-up of their own: [an OAuth2 BFF for a single-page application, end to end]({{ site.baseurl }}/articles/bff/) and [one refresh token flow at a time]({{ site.baseurl }}/articles/refresh-token-stampede/).

We keep complete control over what is auto-configured. Almost every auto-configured component is `@ConditionalOnMissingBean`, so spring-addons backs off as soon as the application defines its own bean, and overriding a default means defining that one bean, not a whole `Security(Web)FilterChain`. The auto-configured filter chains have the lowest precedence, so an application can add its own chains with stricter security matchers. The [risks, in both directions]({{ site.baseurl }}/oidc/risks/) page is worth two minutes before adopting.

When not to use it: a server-rendered application with `oauth2Login` and no JavaScript caller is well served by Spring Security's defaults, and a team which wants to own every security bean should write them and read [what you would write without spring-addons]({{ site.baseurl }}/without-spring-addons/) as a checklist.

## Documentation and tutorials

A few weeks of trial and error can save fifteen minutes of reading a page. Three tutorials from this repo now live on Baeldung:

- [Getting started with Keycloak and Spring Boot](https://www.baeldung.com/spring-boot-keycloak)
- [Creating an OAuth2 BFF with `spring-cloud-gateway` and consuming it from a single-page application](https://www.baeldung.com/spring-cloud-gateway-bff-oauth2)
- [Testing access control with mocked OAuth2 authentications](https://www.baeldung.com/spring-oauth-testing-access-control)

Also useful: the [runnable samples]({{ site.baseurl }}/samples/), the [release notes](https://github.com/ch4mpy/spring-addons/blob/master/release-notes.md), [`llms.txt`](https://github.com/ch4mpy/spring-addons/blob/master/llms.txt) when a coding assistant is involved, and [contributing](https://github.com/ch4mpy/spring-addons/blob/master/CONTRIBUTING.md).
