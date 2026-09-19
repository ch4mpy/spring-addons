package com.c4_soft.springaddons.rest.synchronised;

import java.net.http.HttpClient.Version;
import java.time.Duration;
import java.util.Optional;
import java.util.function.Consumer;
import org.eclipse.jetty.client.HttpProxy;
import org.eclipse.jetty.client.Origin;
import org.eclipse.jetty.client.Request;
import org.eclipse.jetty.client.transport.HttpClientTransportOverHTTP;
import org.eclipse.jetty.http2.client.HTTP2Client;
import org.eclipse.jetty.http2.client.transport.HttpClientTransportOverHTTP2;
import org.eclipse.jetty.io.ClientConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.ClientHttpRequestFactorySettings;
import org.springframework.boot.http.client.JettyClientHttpRequestFactoryBuilder;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.http.client.JettyClientHttpRequestFactory;
import com.c4_soft.springaddons.rest.ProxySupport;
import com.c4_soft.springaddons.rest.RestMisconfigurationException;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * Isolates every reference to {@code org.eclipse.jetty:jetty-client} (and the HTTP/2 transport)
 * types so that this class is loaded (and its bytecode verified) only when a REST client is
 * actually configured with the JETTY implementation.
 * </p>
 * <p>
 * {@link SpringAddonsClientHttpRequestFactoryMerger} must never import any Jetty client type
 * directly: doing so would make class-loading of the merger itself fail with a
 * {@link NoClassDefFoundError} for consumers who don't have jetty-client on the class-path (it is
 * an optional dependency of spring-addons-starter-rest), even when they never use the JETTY
 * implementation.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Slf4j
class JettyRequestFactoryBuilderCustomizer {

  private JettyRequestFactoryBuilderCustomizer() {}

  @SuppressWarnings("unchecked")
  static ClientHttpRequestFactoryBuilder<JettyClientHttpRequestFactory> customize(
      JettyClientHttpRequestFactoryBuilder builder, @Nullable ProxySupport proxySupport,
      boolean proxyActive, boolean sslValidationDisabled,
      Optional<java.util.concurrent.Executor> virtualThreadsExecutor,
      Optional<Version> httpProtocolVersion, Optional<Consumer<?>> httpClientBuilderConsumer) {
    final Consumer<org.eclipse.jetty.client.HttpClient> httpClientCustomizer = client -> {
      if (proxyActive) {
        // the flag is whether the connection to the proxy itself is TLS, not whether the proxy
        // requires credentials (Proxy-Authorization is set on requests by the request factory)
        final var secure = "https".equalsIgnoreCase(proxySupport.getProtocol());
        final var httpProxy = new HttpProxy(
            new Origin.Address(proxySupport.getHostname().get(), proxySupport.getPort()), secure);
        client.getProxyConfiguration().addProxy(httpProxy);
      }
      if (sslValidationDisabled) {
        client.setSslContextFactory(new SslContextFactory.Client(true));
      }
      virtualThreadsExecutor.ifPresent(client::setExecutor);
      httpClientBuilderConsumer.ifPresent(
          c -> ((Consumer<org.eclipse.jetty.client.HttpClient>) (Consumer<?>) c).accept(client));
    };
    if (httpProtocolVersion.isEmpty()) {
      return builder.withHttpClientCustomizer(httpClientCustomizer);
    }
    // Spring Boot 3.5 JettyClientHttpRequestFactoryBuilder always creates an HTTP/1.1 transport
    // and exposes no hook to replace it (Boot 4 has withHttpClientTransportFactory). When a
    // protocol version is forced, the Jetty HttpClient is assembled here instead, mirroring what
    // Boot's JettyHttpClientBuilder does with the settings (SSL bundle, timeouts, redirects).
    final var version = httpProtocolVersion.get();
    log.info(
        "http-protocol-version {} with the Jetty implementation: building a dedicated Jetty HttpClient (customizers registered on the context ClientHttpRequestFactoryBuilder are not applied)",
        version);
    return settings -> {
      final var connector = new ClientConnector();
      if (settings.sslBundle() != null) {
        connector.setSslContextFactory(sslContextFactory(settings.sslBundle()));
      }
      final var transport = switch (version) {
        case HTTP_1_1 -> new HttpClientTransportOverHTTP(connector);
        case HTTP_2 -> {
          try {
            yield new HttpClientTransportOverHTTP2(new HTTP2Client(connector));
          } catch (NoClassDefFoundError e) {
            throw new RestMisconfigurationException(
                "http-protocol-version HTTP_2 with the Jetty implementation requires org.eclipse.jetty.http2:jetty-http2-client and jetty-http2-client-transport on the class-path");
          }
        }
      };
      final var httpClient = new HttpClientWithReadTimeout(transport, settings.readTimeout());
      if (settings.connectTimeout() != null) {
        httpClient.setConnectTimeout(settings.connectTimeout().toMillis());
      }
      if (settings.redirects() != null) {
        httpClient.setFollowRedirects(switch (settings.redirects()) {
          case FOLLOW_WHEN_POSSIBLE, FOLLOW -> true;
          case DONT_FOLLOW -> false;
        });
      }
      httpClientCustomizer.accept(httpClient);
      final var factory = new JettyClientHttpRequestFactory(httpClient);
      if (settings.readTimeout() != null) {
        factory.setReadTimeout(settings.readTimeout());
      }
      return factory;
    };
  }

  private static SslContextFactory.Client sslContextFactory(SslBundle sslBundle) {
    final var sslContextFactory = new SslContextFactory.Client();
    sslContextFactory.setSslContext(sslBundle.createSslContext());
    final var options = sslBundle.getOptions();
    if (options.getCiphers() != null) {
      sslContextFactory.setIncludeCipherSuites(options.getCiphers());
    }
    if (options.getEnabledProtocols() != null) {
      sslContextFactory.setIncludeProtocols(options.getEnabledProtocols());
    }
    return sslContextFactory;
  }

  /**
   * Same as Boot's {@code JettyHttpClientBuilder.HttpClientWithReadTimeout}: applies the read
   * timeout as the timeout of each request when set.
   */
  private static class HttpClientWithReadTimeout extends org.eclipse.jetty.client.HttpClient {
    private final @Nullable Duration readTimeout;

    HttpClientWithReadTimeout(org.eclipse.jetty.client.HttpClientTransport transport,
        @Nullable Duration readTimeout) {
      super(transport);
      this.readTimeout = readTimeout;
    }

    @Override
    public Request newRequest(java.net.URI uri) {
      final var request = super.newRequest(uri);
      if (readTimeout != null) {
        request.timeout(readTimeout.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
      }
      return request;
    }
  }
}
