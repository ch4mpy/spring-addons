package com.c4_soft.springaddons.rest;

import java.time.Duration;
import java.util.Optional;
import javax.net.ssl.SSLException;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslOptions;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties.ClientHttpRequestFactoryImpl;
import io.netty.channel.ChannelOption;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import lombok.extern.slf4j.Slf4j;
import reactor.netty.http.client.HttpClient;

/**
 * <p>
 * Merges spring-addons WebClient HTTP customization (proxy, timeouts, SSL bundle, SSL certificates
 * validation) with the {@link ClientHttpConnector} bean resolved from the context by Spring Boot
 * auto-configuration.
 * </p>
 * <p>
 * Spring Boot 3.4 has no reactive {@code ClientHttpConnectorBuilder} / settings (they came with
 * 3.5): when nothing needs to be added, the context {@link ClientHttpConnector} bean is reused
 * as-is; when a client requires customization, a dedicated Reactor Netty connector is built for
 * that client only, applying the SSL bundle the same way Boot's own connector factory does.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Slf4j
class ClientHttpConnectorMerger {

  private ClientHttpConnectorMerger() {}

  static ClientHttpConnector merge(String clientId, SystemProxyProperties systemProxyProperties,
      ClientHttpRequestFactoryProperties addonsHttp, Optional<String> sslBundleName,
      Optional<SslBundle> resolvedSslBundle, Optional<ClientHttpConnector> contextConnector) {

    final var proxySupport = new ProxySupport(systemProxyProperties, addonsHttp.getProxy());
    final var proxyActive = proxySupport.isEnabled();
    final var sslValidationDisabled = !addonsHttp.isSslCertificatesValidationEnabled();

    warnAboutUnsupportedProperties(clientId, addonsHttp);

    final var needsCustomization = proxyActive || sslValidationDisabled
        || addonsHttp.getConnectTimeoutMillis().isPresent()
        || addonsHttp.getReadTimeoutMillis().isPresent() || sslBundleName.isPresent();

    if (!needsCustomization) {
      final var connector = contextConnector.orElseGet(ReactorClientHttpConnector::new);
      log.info("WebClient '{}' HTTP connector: {} ({})", clientId,
          contextConnector.isPresent() ? "reused unmodified from context"
              : "built with defaults (no ClientHttpConnector bean found in context)",
          connector.getClass().getSimpleName());
      return connector;
    }

    var client = HttpClient.create();
    if (addonsHttp.getConnectTimeoutMillis().isPresent()) {
      client = client.option(ChannelOption.CONNECT_TIMEOUT_MILLIS,
          addonsHttp.getConnectTimeoutMillis().get());
    }
    if (addonsHttp.getReadTimeoutMillis().isPresent()) {
      client = client.responseTimeout(Duration.ofMillis(addonsHttp.getReadTimeoutMillis().get()));
    }
    if (proxyActive) {
      client = ReactorProxySupport.withProxy(client, proxySupport);
    }
    if (sslValidationDisabled) {
      if (sslBundleName.isPresent()) {
        log.warn(
            "WebClient '{}': ssl-bundle '{}' is ignored because ssl-certificates-validation-enabled is false",
            clientId, sslBundleName.get());
      }
      try {
        final var sslContext = SslContextBuilder.forClient()
            .trustManager(InsecureTrustManagerFactory.INSTANCE).build();
        client = client.secure(t -> t.sslContext(sslContext));
      } catch (SSLException e) {
        throw new RestMisconfigurationException(e);
      }
    } else if (resolvedSslBundle.isPresent()) {
      client = withSslBundle(client, resolvedSslBundle.get());
    }

    final var connector = new ReactorClientHttpConnector(client);
    log.info("WebClient '{}' HTTP connector: built a dedicated Reactor instance ({})", clientId,
        connector.getClass().getSimpleName());
    return connector;
  }

  /**
   * Same as Spring Boot's {@code ReactorClientHttpConnectorFactory}: key and trust managers,
   * ciphers and protocols of the bundle applied to the Reactor Netty client.
   */
  private static HttpClient withSslBundle(HttpClient client, SslBundle sslBundle) {
    return client.secure(spec -> {
      final var options = sslBundle.getOptions();
      final var managers = sslBundle.getManagers();
      final var builder = SslContextBuilder.forClient().keyManager(managers.getKeyManagerFactory())
          .trustManager(managers.getTrustManagerFactory())
          .ciphers(SslOptions.asSet(options.getCiphers()))
          .protocols(options.getEnabledProtocols());
      try {
        spec.sslContext(builder.build());
      } catch (SSLException e) {
        throw new RestMisconfigurationException(e);
      }
    });
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
          "WebClient '{}': http-client-builder-consumer-bean '{}' is ignored, customize the WebClient.Builder bean or the ClientHttpConnector bean instead",
          clientId, addonsHttp.getHttpClientBuilderConsumerBean().get());
    }
  }

}
