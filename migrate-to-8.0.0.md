# Migrating from `7.x` to `8.x`

## `spring-addons-starter-oidc`

The only breaking changes are around `OAuthentication` which now extends `AbstractOAuth2TokenAuthenticationToken` for a better integration with the rest of the Spring Security ecosystem.

If using `OpenidClaimSet` directly, wrap it in an `OpenidToken`; if extending it, extend `OpenidToken` instead.

Move the token string argument from the `OAuthentication` constructor to the `principal` one (probably an `OpenidToken`).

```java
new OAuthentication<>(new OpenidClaimSet(claims), authorities, tokenString);
```
becomes
```java
new OAuthentication<>(new OpenidToken(new OpenidClaimSet(claims), tokenString), authorities);
```

## `spring-addons-starter-rest`

`SpringAddonsRestClientSupport`, `SpringAddonsWebClientSupport`, and `ReactiveSpringAddonsWebClientSupport` are replaced by `ProxyFactoryBean`s:
- `RestClient` and `WebClient` bean definitions (or the definition of their builders) are registered as bart of the bean registry post processing => remove any explicit bean definition in application conf, the Boot starter does it already.
- change `@HttpExchange` service proxy bean defintions to use `RestClientHttpExchangeProxyFactoryBean` or `WebClientHttpExchangeProxyFactoryBean`

Proxy properties are now configurable for each client => in YAML, move it down one level (copy it to each client needing proxy configuration).

There are more configuration options available:
- a flag to expose the client builder inttead of an already built client
- force the bean name (by default, it's the camelCase transformation of the kebab-case client ID in properties, with `Builder` suffix when `expose-builder` is `true`)
- set connect and read timeouts
- expose a `WebClient` instead of the default `RestClient` in a servlet application
- set chunk-size (only applied to `RestClient`)