---
title: Usage
parent: spring-addons-starter-rest
nav_order: 1
description: "Declaring RestClient and WebClient beans from properties: base URL, Basic and Bearer authorization, forwarding the token in the security context, and backing @ImportHttpServices groups with an auto-configured client."
---

# Usage


To take the most value from the `RestClient`/`WebClient`, we may provide it to [`@HttpExchange` proxy factories](#backing-importhttpservices-groups-with-an-auto-configured-client).

As a reminder, `@HttpExchange` interfaces describe a REST API from the client's point of view. The proxies mentioned above are generated implementations to consume this API. We can see it as a REST equivalent to what `@Repository` is for relational databases.

If the consumed REST API exposes an OpenAPI spec (using Swagger, maybe through [`springdoc-openapi`](https://springdoc.org/) and [Swagger annotations](https://github.com/swagger-api/swagger-core/wiki/Swagger-2.X---Annotations)), the `@HttpExchange` interfaces can be generated using the [`openapi-generator-maven-plugin`](https://github.com/OpenAPITools/openapi-generator/tree/master/modules/openapi-generator-maven-plugin) or [`openapi-generator-gradle-plugin`](https://github.com/OpenAPITools/openapi-generator/tree/master/modules/openapi-generator-gradle-plugin). 

In other words, we can consume REST APIs with almost zero boilerplate code:
1. generate the OpenAPI spec of REST APIs from their sources
2. generate the `@HttpExchange` interfaces describing how clients can consume these APIs from the OpenAPI specs
3. generate `@HttpExchange` proxies, providing each with a `RestClient`/`WebClient` bean auto-configured by `spring-addons-starter-rest`

The following describes the last point. Refer to the docs linked above to generate the OpenAPI spec from `@RestController` sources or to generate `@HttpExchange` from this spec.

## Dependency
```xml
<dependency>
    <groupId>com.c4-soft.springaddons</groupId>
    <artifactId>spring-addons-starter-rest</artifactId>
    <version>${spring-addons.version}</version>
</dependency>
```

This starter declares `spring-boot-restclient` and `spring-boot-webclient` as **optional**, so the application must bring the client support it actually uses. Without it, the auto-configured beans fail with `Type org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder not present` (or its reactive equivalent):
```xml
<!-- for RestClient beans (the default in a servlet application) -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-restclient</artifactId>
</dependency>
<!-- for WebClient beans (the default in a reactive application, also usable in a servlet one) -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-webclient</artifactId>
</dependency>
```
`spring-boot-starter-webflux` already pulls the `WebClient` support, so a reactive application needs nothing more.

To authorize requests with `authorization.oauth2.oauth2-registration-id`, `spring-boot-starter-security-oauth2-client` is required too (and `spring-boot-starter-security-oauth2-resource-server` for `forward-bearer`, which reads the token from the security context of a resource server).

## Minimal sample
```yaml
com:
  c4-soft:
    springaddons:
      rest:
        client:
          keycloak-admin-client:
            base-url: ${keycloak-base-uri}/admin/realms
            authorization:
              oauth2:
                forward-bearer: true
```
This exposes a pre-configured bean named `keycloakAdminClient`. The default type of this bean is `RestClient` in a servlet app and `WebClient` in a Webflux one.

## Advanced configuration samples
```yaml
machin-api-base-url: http://localhost:8081
com:
  c4-soft:
    springaddons:
      rest:
        client:
          # this exposes a bean named "machinClient"
          machin-client:
            # Easy to override in each deployment (for instance with MACHIN_API_BASE_URL environment variable)
            base-url: ${machin-api-base-url}
            http:
              connect-timeout-millis: 1000
              read-timeout-millis: 1000
              # requires org.apache.httpcomponents.client5:httpclient5 to be on the class-path
              client-http-request-factory-impl: http-components
              # disable SSL certificates validation
              # when "client-http-request-factory-impl" is "jdk", only root authority validation is disabled (not the hostname, so the certificate CN or altnames must match the URL hostame)
              ssl-certificates-validation-enabled: false
              # Override what is defined in HTTP_PROXY and NO_PROXY environment variables
              proxy:
                connect-timeout-millis: 500
                enabled: true
                host: proxy2.corporate.pf
                non-proxy-hosts-pattern: .+\.corporate\.pf
                username: spring-backend
                password: secret
                port: 8080
                protocol: http
            authorization:
              oauth2:
                # authorize outgoing requests with the Bearer token in the security (possible only in a resource server app)
                forward-bearer: true
          # this exposes a bean named "biduleClientBuilder" (mind the "expose-builder: true" below)
          bidule-client:
            base-url: http://localhost:${bidule-api-port}
            # expose the RestClient.Builder instead of an already built RestClient.
            # The "Builder" suffix is added to the default bean name ("bidule-client" -> "biduleClient" -> "biduleClientBuilder" in this case)
            expose-builder: true
            authorization:
              oauth2:
                # authorize outgoing requests with a Bearer obtained using an OAuth2 client registration
                oauth2-registration-id: bidule-registration
            http:
              proxy:
                # use HTTP_PROXY and NO_PROXY environment variables and add proxy authentication
                username: spring-backend
                password: secret
          chose-client:
            base-url: http://localhost:${chose-api-port}
            # expose a WebClient instead of a RestClient in a servlet app
            type: WEB_CLIENT
            # change the bean name to "chose" (would be "choseClient" by default)
            bean-name: chose
            authorization:
              # authorize outgoing requests with Basic auth
              basic:
                username: spring-backend
                password: secret
            http:
              proxy:
                # Ignore HTTP_PROXY environment variable
                enabled: false
          chouette-client:
            base-url: https://something.pf/api
            # add headers with static values
            headers:
              X-API-KEY: change-me
              X-MULTI-VALUED-HEADER: 
              - foo
              - bar
              - bam
```
The `biduleClientBuilder` bean can be used to define a `biduleClient` bean as follows:
```java
/** 
 * @param biduleClientBuilder pre-configured using application properties
 * @return a {@link RestClient} bean named "biduleClient"
 */
@Bean
RestClient biduleClient(RestClient.Builder biduleClientBuilder) throws Exception {
  // Fine-tune biduleClientBuilder configuration
  return biduleClientBuilder.build();
}
```

## Backing `@ImportHttpServices` groups with an auto-configured client

Since Spring Framework 7, `@ImportHttpServices` registers `@HttpExchange` proxies organized in named groups, each with its own `RestClient`/`WebClient`. `spring-addons-starter-rest` can back such a group with an already auto-configured client from `com.c4-soft.springaddons.rest.client`.

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

```java
@Configuration
@ImportHttpServices(group = "keycloak-group", types = {UsersApi.class, ClientRoleMappingsApi.class})
class HttpServicesConfiguration {
}
```

The client keeps existing as an independently injectable bean.

Several groups can reference the same client-id, for instance to split one API's `@HttpExchange` interfaces across multiple `@ImportHttpServices` declarations without duplicating configuration. Groups with no matching entry under `com.c4-soft.springaddons.rest.group` are left to Spring Boot's own resolution (`spring.http.serviceclient.*` properties and any `HttpServiceGroupConfigurer` bean the application registers).

