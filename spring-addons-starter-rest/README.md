# Spring Boot starter for `RestClient`, `WebClient` and `@HttpExchange` proxies auto-configuration
This starter brings some experimental auto-configuration for `RestClient` and `WebClient`. For now, it supports:
- proxy settings
- base URL
- Basic authorization
- OAuth2 Bearer authorization:
  * the `(Reactive)OAuth2AuthorizedClientManager` for a given registration-id (configurable per client)
  * the security context of a request on a resource server (forward the Bearer token from the original request)

It also eases the creation of `@HttpExchange` proxies, the successor of `@FeignClient`.

## Usage
### Dependency
```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starters-rest</artifactId>
    <version>${spring-addons.version}</version>
</dependency>
```

### Pre-configured `RestClient` & `WebClient` builders
The following helper beans are provided:
- `SpringAddonsRestClientSupport` in all servlet applications
- `SpringAddonsWebClientSupport` only in servlet applications with `WebClient` on the class-path
- `ReactiveSpringAddonsWebClientSupport` in all reactive applications

The three provide with helper to get `RestClient` and `WebClient` builders pre-configured with:
- `base-url`: as this URI is very likely to change from a deploying environment to another, it is taken from application properties.
- OAuth2 authorization: a choice of at most one of the following strategies can be done:
  * `auth2-registration-id`: the `(Reactive)OAuth2AuthorizedClientManager` is used to get an access token, using the provided registration-id
  * `forward-bearer`: this is of interest when the REST request is send from an `oauth2ResourceServer`, to forward the access token in the security context. In that case, no Spring configuration for a `provider` or `registration` is needed. The `DefaultBearerProvider` works only with `JwtAuthenticationToken` and `BearerTokenAuthentication`, so if your authentication manager builds something exotic, expose your own `BearerProvider` bean.
- Basic authentication
- proxy

Let's explore a sample with the following configuration:
```yaml
keycloak-base-uri: https://localhost:8443/auth
issuer: ${keycloak-base-uri}/realms/master
keycloak-admin-api-consumer-secret: change-me

spring:
  security:
    oauth2:
      client:
        provider:
          keycloak:
           issuer-uri: ${issuer}
        registration:
          backend-with-client-credentials:
            provider: keycloak
            authorization-grant-type: client_credentials
            client-id: keycloak-admin-api-consumer
            client-secret: ${keycloak-admin-api-consumer-secret}

com:
  c4-soft:
    springaddons:
      oidc:
        ops:
        - iss: https://localhost:8443/auth/realms/master
        resourceserver:
          permit-all: /public/**
      rest:
        client:
          keycloak-admin-api:
            base-url: ${keycloak-base-uri}/admin/realms
            authorization:
              oauth2:
                oauth2-registration-id: backend-with-client-credentials
```
`keycloak-admin-api` is a key for a REST client configuration which can be used as follow:
```java
@Bean(name = "keycloakAdminApiClient")
RestClient keycloakAdminApiClient(SpringAddonsRestClientSupport restSupport) {
    final var client = restSupport.client("keycloak-admin-api");
    // if needed, tune the client here
    return client.build();
}
```
Depending on the support bean you use, you'll get as client:
- `SpringAddonsRestClientSupport`: a `RestClient.Builder`
- `SpringAddonsWebClientSupport`: a `WebClient.Builder` for a servlet application
- `ReactiveSpringAddonsWebClientSupport`: : a `WebClient.Builder` for a reactive application

### `@HttpExchange` proxies

The REST support beans described above also provide with methods to build `@HttpExchange` proxies. Let's consider the following `KeycloakAdminApi` interface:
```java
@HttpExchange(accept = MediaType.APPLICATION_JSON_VALUE)
public interface KeycloakAdminApi {

    @GetExchange(url = "/{realm}/users/count")
    Long getTotalUsersCount(@PathVariable(name = "realm") String realm);
}
```
An implementation for the `KeycloakAdminApi` is auto-magically provided by Spring and can be injected in your own components with just the following:
```java
@Bean
KeycloakAdminApi keycloakAdminApi(SpringAddonsRestClientSupport restSupport) {
    return restSupport.service("keycloak-admin-api", KeycloakAdminApi.class);
}
```
Where `keycloak-admin-api` is an entry under `com.c4-soft.springaddons.oidc.client.rest` (as demonstrated in the preceding section).
