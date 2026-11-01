---
title: Spring AOT and native images
nav_order: 12
description: "How the spring-addons starters behave with Spring AOT (spring-boot:process-aot, AOT on the JVM, GraalVM native images): what is decided at build time, the runtime hints the libraries contribute, and those an application adds."
---

# Spring AOT and native images
{: .no_toc }

Since `9.7.1`, the spring-addons starters work with Spring AOT: `spring-boot:process-aot`, an AOT-processed application on the JVM (`-Dspring.aot.enabled=true`), and GraalVM native images.

1. TOC
{:toc}

## What is decided at build time

Spring AOT evaluates the conditions of the auto-configurations when it generates the code, and freezes them: the generated application has the beans of the build-time environment, as for any Spring Boot application. For spring-addons, this means that the profiles and properties active during `process-aot` decide:

- whether the application is a resource server, a client with `oauth2Login`, or both, and whether a resource server decodes JWTs or introspects opaque tokens (`spring.security.oauth2.resourceserver.opaquetoken.introspection-uri`);
- which `com.c4-soft.springaddons.rest` clients exist, their type (`RestClient` or `WebClient`), whether they expose a builder and whether they authorize requests with OAuth2;
- which profile-specific `@Configuration` classes are kept: in the [`resource-server` sample](https://github.com/ch4mpy/spring-addons/tree/master/samples/resource-server), the `introspection` profile must be active during `process-aot` for its introspection converter to be in the generated code.

Values are still read at runtime: issuer URIs, client secrets, base URLs, proxies, CORS settings, authorities mapping... An AOT-processed application can be built once and deployed in several environments, as long as they use the same features.

## Runtime hints

A native image knows only the reflection, resources and proxies declared to GraalVM. Spring AOT infers most of them, and the spring-addons libraries contribute the others they need:

| Module | Hints contributed |
|---|---|
| `spring-addons-oauth2` | The constructors of the JsonPath functions (`keys()`, `first()`, `concat()`...) used in claim paths, and the public methods of `SpringAddonsMethodSecurityExpressionRoot` (`this`, `returnObject`, `filterObject` in method security expressions) |
| `spring-addons-starter-recaptcha` | The `siteverify` response DTOs, which Jackson binds by reflection |

An application declares hints of its own for what spring-addons can't know about:

- **The methods of its own expression root**, a subclass of `SpringAddonsMethodSecurityExpressionRoot` given to `SpringAddonsMethodSecurityExpressionHandler`: SpEL calls them by reflection.

  ```java
  @Configuration
  @RegisterReflection(classes = MyExpressionRoot.class, memberCategories = MemberCategory.INVOKE_PUBLIC_METHODS)
  class SecurityConfig {
  }
  ```

- **The types it binds by reflection itself**, as in any native application: the bodies of `RestClient` / `WebClient` calls made outside an `@HttpExchange` interface, for instance, with `@RegisterReflectionForBinding`.

## Spring Cloud

Spring Cloud's refresh scope is not compatible with AOT. An application using Spring Cloud, like the [`bff` sample](https://github.com/ch4mpy/spring-addons/tree/master/samples/bff) (Spring Cloud Gateway), sets `spring.cloud.refresh.enabled=false` during `process-aot` and at runtime.

## How it is checked

- The CI processes the samples ahead of time and runs their tests on the generated contexts: the `aot` profile of the samples, `./mvnw -Paot clean install`.
- The hints are tested in each module with `RuntimeHintsPredicates`.
- For `9.7.1`, a native image of a probe application (JsonPath functions, method security expressions with a custom root, reCAPTCHA validation) was built with GraalVM 25. The build does not produce native images, which take minutes each.
