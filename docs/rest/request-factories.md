---
title: HTTP client and proxies
parent: spring-addons-starter-rest
nav_order: 2
description: "Changing the ClientHttpRequestFactory of an auto-configured client: switching the underlying HTTP library, timeouts, and HTTP proxies from the HTTP_PROXY and NO_PROXY environment variables."
---

# Changing the default `ClientHttpRequestFactory`

Since Spring Boot 4, a `ClientHttpRequestFactory` (built from a `ClientHttpRequestFactoryBuilder` and `HttpClientSettings`) is always present in the context, honoring `spring.http.clients.*` properties and any `ClientHttpRequestFactoryBuilderCustomizer` registered by the application. The default `client-http-request-factory-impl` is `FROM_CONTEXT`: for each REST client, `spring-addons-starter-rest` reuses that context bean unmodified when no spring-addons-specific customization (proxy, timeouts, disabled SSL certificates validation, protocol version, virtual threads, consumer bean) is required, and enriches a dedicated copy of the context builder (never mutating the shared bean) otherwise. Enrichment is supported when the context builder is `HttpComponentsClientHttpRequestFactoryBuilder`, `JdkClientHttpRequestFactoryBuilder`, `JettyClientHttpRequestFactoryBuilder`, `ReactorClientHttpRequestFactoryBuilder` or `SimpleClientHttpRequestFactoryBuilder`; for any other builder type (typically an application-provided `of(...)`), a `RestMisconfigurationException` is thrown naming the client and the builder type if customization is actually needed for that client. The Reactor and Simple implementations also reject, with the same exception, whichever customization they cannot honor themselves (see the table below).

`client-http-request-factory-impl` can also be forced to `JDK`, `HTTP_COMPONENTS`, `JETTY`, `REACTOR` or `SIMPLE`: in that case, the context builder is ignored and a fresh instance is always built with the selected implementation, exactly as before Spring Boot 4 introduced auto-configured HTTP client beans.

> [!NOTE]
> If both `ssl-bundle` and `ssl-certificates-validation-enabled: false` are configured for the same client, disabling validation wins: a WARN log names the client and the ignored bundle. The same rule applies on the `WebClient` side (see [SSL bundles]({{ site.baseurl }}/rest/ssl-bundles/)).

Three extra properties tune the underlying HTTP client: `http-protocol-version` forces the HTTP protocol version, `use-virtual-threads` sets the application task executor (the `applicationTaskExecutor` bean, virtual-thread when `spring.threads.virtual.enabled=true`) on the client, and `http-client-builder-consumer-bean` names a `Consumer` bean applied to the implementation-specific client builder just before the request factory is built — for whatever is not exposed as properties. Support depends on the implementation, as detailed in the comments below:
```yaml
com:
  c4-soft:
    springaddons:
      rest:
        client:
          jdk-sample-client:
            http:
              # both HTTP_1_1 and HTTP_2 are supported
              http-protocol-version: HTTP_2

              # requires spring.threads.virtual.enabled to be true
              # you probably don't need to set this property as it defaults to ${spring.threads.virtual.enabled}
              use-virtual-threads: ${spring.threads.virtual.enabled}

              # the name of a Consumer<java.net.http.HttpClient.Builder> bean
              http-client-builder-consumer-bean: jdkHttpClientBuilderConsumer

          httpcomponents-sample-client:
            http:
              # requires org.apache.httpcomponents.client5:httpclient5 to be on the class-path
              client-http-request-factory-impl: http-components

              # these properties are ignored for httpcomponents
              http-protocol-version:
              use-virtual-threads:

              # the name of a Consumer<org.apache.hc.client5.http.impl.classic.HttpClientBuilder> bean
              http-client-builder-consumer-bean: httpComponentsHttpClientBuilderConsumer

          jetty-sample-client:
            http:
              # requires org.eclipse.jetty:jetty-client to be on the class-path
              client-http-request-factory-impl: jetty
              # HTTP_2 also requires org.eclipse.jetty.http2:jetty-http2-client and jetty-http2-client-transport to be on the class-path
              http-protocol-version: HTTP_2
              use-virtual-threads: ${spring.threads.virtual.enabled}

              # the name of a Consumer<org.eclipse.jetty.client.HttpClient> bean
              http-client-builder-consumer-bean: jettyHttpClientBuilderConsumer

          reactor-sample-client:
            http:
              # requires io.projectreactor.netty:reactor-netty-http to be on the class-path
              # (typically pulled in transitively by spring-boot-starter-webflux)
              client-http-request-factory-impl: reactor

              # these properties are rejected (RestMisconfigurationException) for reactor: its
              # underlying reactor.netty.http.client.HttpClient is immutable, runs on its own
              # event-loop threads, and does not expose HTTP protocol version selection here
              http-protocol-version:
              use-virtual-threads:
              http-client-builder-consumer-bean:

          simple-sample-client:
            http:
              # java.net.HttpURLConnection based, always on the class-path
              client-http-request-factory-impl: simple

              # rejected (RestMisconfigurationException): HttpURLConnection is always HTTP/1.1,
              # offers no executor hook, and SimpleClientHttpRequestFactory has no SSL customization hook
              ssl-certificates-validation-enabled: true
              http-protocol-version:
              use-virtual-threads:

              # the name of a Consumer<org.springframework.http.client.SimpleClientHttpRequestFactory> bean
              http-client-builder-consumer-bean: simpleHttpClientBuilderConsumer
```
With:
```java
@Bean
Consumer<java.net.http.HttpClient.Builder> jdkHttpClientBuilderConsumer() {
  return builder -> { /* TODO: implement */ };
}

@Bean
Consumer<org.apache.hc.client5.http.impl.classic.HttpClientBuilder> httpComponentsHttpClientBuilderConsumer() {
  return builder -> { /* TODO: implement */ };
}

@Bean
Consumer<org.eclipse.jetty.client.HttpClient> jettyHttpClientBuilderConsumer() {
  return builder -> { /* TODO: implement */ };
}

@Bean
Consumer<org.springframework.http.client.SimpleClientHttpRequestFactory> simpleHttpClientBuilderConsumer() {
  return factory -> { /* TODO: implement */ };
}
```

