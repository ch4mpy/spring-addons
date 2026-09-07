# Migrating from `9.1.x` to `9.2.x`

## `spring-addons-starter-rest`

### Default `client-http-request-factory-impl` changed from `JDK` to `FROM_CONTEXT`

Since Spring Boot 4, a `ClientHttpRequestFactory` (and `ClientHttpConnector` for `WebClient`) is always present in the context, built by Boot's own auto-configuration from `spring.http.clients.*` properties and any `ClientHttpRequestFactoryBuilderCustomizer` registered by the application. `spring-addons-starter-rest` now reuses that context bean (or an enriched copy of its builder, never mutating the shared bean) instead of silently ignoring it.

Impact:
- If your application relies on `spring.http.clients.*` or a `ClientHttpRequestFactoryBuilderCustomizer` bean to configure REST clients, those settings are now honored where before they were silently overridden by spring-addons.
- If a REST client requires spring-addons customization (proxy, timeouts, `ssl-certificates-validation-enabled: false`, `http-protocol-version`, `use-virtual-threads`, `http-client-builder-consumer-bean`) and the context `ClientHttpRequestFactoryBuilder` is neither HttpComponents, JDK nor Jetty (for instance because an application replaced it with a Reactor or a custom `of(...)` builder), a `RestMisconfigurationException` is now thrown naming the client and the builder type. Force `client-http-request-factory-impl` to `JDK`, `HTTP_COMPONENTS` or `JETTY` for that client to restore the previous behavior (a dedicated instance built from scratch, ignoring the context builder).
- To keep the exact pre-9.2.0 behavior for a given client, set `client-http-request-factory-impl: jdk` explicitly.

### `ssl-bundle` no longer silently overridden by proxy/timeouts customization

Before `9.2.0`, configuring both `ssl-bundle` and any spring-addons HTTP customization (proxy, timeouts, ...) on the same REST client or `WebClient` resulted in the `ssl-bundle` configuration being silently discarded. Both can now be combined. The only remaining priority rule is: if `ssl-certificates-validation-enabled: false` is also set, it wins over `ssl-bundle`, with a WARN log naming the client and the ignored bundle.

### `ssl` field removed from `RestClientFactoryBean`/`RestClientBuilderFactoryBean`/`AbstractWebClientBuilderFactoryBean`

If you extended one of these classes and relied on the autowired `ssl` field (`RestClientSsl`/`WebClientSsl`) to apply an SSL bundle yourself, resolve the bundle directly instead: `applicationContext.getBean(SslBundles.class).getBundle(bundleName)`.
