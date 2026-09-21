---
title: Testing access control
nav_order: 6
has_children: true
description: "Testing OAuth2 access control in Spring Boot: annotations which populate the security context on any @Component, running the authentication converter of the application instead of a stub Authentication."
---

# Testing access control
{: .no_toc }

Testing access control requires a security context populated with a fine-tuned `Authentication`. `spring-security-test` provides `MockMvc` request post-processors and `WebTestClient` mutators, but they work only in the context of a request, which limits them to controllers. To test any kind of `@Component`, including `@Service` and `@Repository`, the options are to build the security context by hand, or to let annotations do it.

## Why not the post-processors and mutators

The authentication converter defined in the security configuration is ignored by the post-processors and mutators. Building the security context in a resource server with a JWT decoder has three steps:

1. the Bearer string is decoded, validated, and turned into a `org.springframework.security.oauth2.jwt.Jwt` by a `JwtDecoder`
2. that `Jwt` is turned into an `AbstractAuthenticationToken` by an authentication converter, which is where claims become authorities and where a custom `Authentication` implementation is chosen
3. the `Authentication` is put in the security context

`@WithJwt` mocks step 1 only: it builds a stub `Jwt` from a JSON payload in test resources and hands it to the authentication converter. The `.jwt()` post-processor jumps to step 3 and builds the `Authentication` itself, so the conversion logic is never exercised.

Note that this requires the authentication converter to be exposed as a `@Bean` rather than inlined as a lambda in the filter chain definition, which `spring-addons-starter-oidc` does out of the box.

```java
@Test
@WithJwt("brice.json") // a JSON claim-set in test resources
void givenUserIsBrice_whenGetMe_thenOk() throws Exception {
    api.get("/greetings/me").andExpect(status().isOk());
}
```

## Where to go next

- [Annotations]({{ site.baseurl }}/testing/annotations/): `@WithMockAuthentication`, `@WithJwt` and `@WithOpaqueToken`, usable on any kind of `@Component`.
- [Test slices]({{ site.baseurl }}/testing/slices/): the companion for applications using `spring-addons-starter-oidc`, with `MockMvcSupport` and `WebTestClientSupport`.
- The Baeldung article [Testing access control with mocked OAuth2 authentications](https://www.baeldung.com/spring-oauth-testing-access-control).
- Every [runnable sample](https://github.com/ch4mpy/spring-addons/tree/master/samples) tests its access control with these annotations.
