package com.c4_soft.springaddons.rest;

import java.time.Duration;
import java.util.Optional;
import javax.net.ssl.SSLException;
import org.springframework.boot.http.client.reactive.ClientHttpConnectorSettings;
import org.springframework.boot.http.client.reactive.ClientHttpConnectorBuilder;
import org.springframework.boot.http.client.reactive.ReactorClientHttpConnectorBuilder;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.http.client.reactive.ClientHttpConnector;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties.ClientHttpRequestFactoryImpl;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * Merges spring-addons WebClient HTTP customization (proxy, timeouts, SSL certificates
 * validation) with the {@link ClientHttpConnectorBuilder} / {@link ClientHttpConnector} beans
 * resolved from the context by Spring Boot auto-configuration.
 * </p>
 * <p>
 * Limited to Reactor Netty: the context builder is enriched when it is a
 * {@link ReactorClientHttpConnectorBuilder}, otherwise a new Reactor builder is forced (no
 * exception is thrown for other connector types, unlike the REST client side, since no reactive
 * JDK, HttpComponents or Jetty connector customization is supported by spring-addons-starter-rest).
  * The context builder is never mutated: when a client requires customization, a dedicated instance
  * is built for that client only. When nothing needs to be added, a connector is built from the
  * (possibly context-provided) builder and settings for that client.
  * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Slf4j
class ClientHttpConnectorMerger {

  private ClientHttpConnectorMerger() {}

  static ClientHttpConnector merge(String clientId, SystemProxyProperties systemProxyProperties,
      ClientHttpRequestFactoryProperties addonsHttp, Optional<String> sslBundleName,
      Optional<SslBundle> resolvedSslBundle,
      Optional<ClientHttpConnectorBuilder<?>> contextBuilder,
      Optional<ClientHttpConnectorSettings> contextSettings) {

    final var proxySupport = new ProxySupport(systemProxyProperties, addonsHttp.getProxy());
    final var proxyActive = proxySupport.isEnabled();
    final var sslValidationDisabled = !addonsHttp.isSslCertificatesValidationEnabled();

    warnAboutUnsupportedProperties(clientId, addonsHttp);

    final var needsCustomization = proxyActive || sslValidationDisabled
        || addonsHttp.getConnectTimeoutMillis().isPresent()
        || addonsHttp.getReadTimeoutMillis().isPresent() || sslBundleName.isPresent();

    if (!needsCustomization) {
      final var builder = contextBuilder.orElseGet(ClientHttpConnectorBuilder::reactor);
      final var settings = contextSettings.orElseGet(ClientHttpConnectorSettings::defaults);
      final var connector = builder.build(settings);
      log.info(
          "WebClient '{}' HTTP connector: built from {} context builder (no customization required)",
          clientId, connector.getClass().getSimpleName());
      return connector;
    }

    final var reactorBuilder =
        contextBuilder.filter(ReactorClientHttpConnectorBuilder.class::isInstance)
            .map(ReactorClientHttpConnectorBuilder.class::cast)
            .orElseGet(ClientHttpConnectorBuilder::reactor);
    final var contextEnriched = contextBuilder.filter(ReactorClientHttpConnectorBuilder.class::isInstance).isPresent();

    var settings = contextSettings.orElseGet(ClientHttpConnectorSettings::defaults);
    if (addonsHttp.getConnectTimeoutMillis().isPresent()) {
      settings =
          settings.withConnectTimeout(Duration.ofMillis(addonsHttp.getConnectTimeoutMillis().get()));
    }
    if (addonsHttp.getReadTimeoutMillis().isPresent()) {
      settings =
          settings.withReadTimeout(Duration.ofMillis(addonsHttp.getReadTimeoutMillis().get()));
    }
    if (sslValidationDisabled) {
      if (sslBundleName.isPresent()) {
        log.warn(
            "WebClient '{}': ssl-bundle '{}' is ignored because ssl-certificates-validation-enabled is false",
            clientId, sslBundleName.get());
      }
    } else if (resolvedSslBundle.isPresent()) {
      settings = settings.withSslBundle(resolvedSslBundle.get());
    }

    final var customizedBuilder = reactorBuilder.withHttpClientCustomizer(client -> {
      var c = client;
      if (proxyActive) {
        c = ReactorProxySupport.withProxy(c, proxySupport);
      }
      if (sslValidationDisabled) {
        try {
          final var sslContext = SslContextBuilder.forClient()
              .trustManager(InsecureTrustManagerFactory.INSTANCE).build();
          c = c.secure(t -> t.sslContext(sslContext));
        } catch (SSLException e) {
          throw new RestMisconfigurationException(e);
        }
      }
      return c;
    });

    final var connector = customizedBuilder.build(settings);
    log.info("WebClient '{}' HTTP connector: {} ({})", clientId,
        contextEnriched ? "context builder enriched" : "built a forced Reactor instance",
        connector.getClass().getSimpleName());

    return connector;
  }

  /**
   * The {@code http.*} properties are shared by RestClient and WebClient definitions, but a
   * WebClient connector is always Reactor Netty based: the properties selecting or customizing the
   * underlying client implementation have no effect on it. Say so instead of ignoring them silently.
   */
  private static void warnAboutUnsupportedProperties(String clientId,
      ClientHttpRequestFactoryProperties addonsHttp) {
    if (addonsHttp.getClientHttpRequestFactoryImpl() != ClientHttpRequestFactoryImpl.FROM_CONTEXT
        && addonsHttp.getClientHttpRequestFactoryImpl() != ClientHttpRequestFactoryImpl.REACTOR) {
      log.warn(
          "WebClient '{}': client-http-request-factory-impl={} is ignored, WebClient connectors are always Reactor Netty based",
          clientId, addonsHttp.getClientHttpRequestFactoryImpl());
    }
    if (addonsHttp.getHttpProtocolVersion().isPresent()) {
      log.warn(
          "WebClient '{}': http-protocol-version is ignored, it is only supported by RestClient JDK and JETTY implementations",
          clientId);
    }
    if (addonsHttp.getUseVirtualThreads().isPresent()) {
      log.warn(
          "WebClient '{}': use-virtual-threads is ignored, Reactor Netty runs on its own event-loop threads",
          clientId);
    }
    if (addonsHttp.getHttpClientBuilderConsumerBean().isPresent()) {
      log.warn(
          "WebClient '{}': http-client-builder-consumer-bean '{}' is ignored, customize the WebClient.Builder bean or the ClientHttpConnectorBuilder instead",
          clientId, addonsHttp.getHttpClientBuilderConsumerBean().get());
    }
  }

}
