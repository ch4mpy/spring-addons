package com.c4_soft.springaddons.rest.synchronised;

import java.net.http.HttpClient.Version;
import java.util.Optional;
import java.util.function.Consumer;
import org.eclipse.jetty.client.Authentication;
import org.eclipse.jetty.client.BasicAuthentication;
import org.eclipse.jetty.client.HttpProxy;
import org.eclipse.jetty.client.Origin;
import org.eclipse.jetty.client.transport.HttpClientTransportOverHTTP;
import org.eclipse.jetty.http2.client.HTTP2Client;
import org.eclipse.jetty.http2.client.transport.HttpClientTransportOverHTTP2;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.http.client.JettyClientHttpRequestFactoryBuilder;
import org.springframework.util.StringUtils;
import com.c4_soft.springaddons.rest.ProxySupport;
import com.c4_soft.springaddons.rest.RestMisconfigurationException;

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
class JettyRequestFactoryBuilderCustomizer {

  private JettyRequestFactoryBuilderCustomizer() {}

  @SuppressWarnings("unchecked")
  static JettyClientHttpRequestFactoryBuilder customize(JettyClientHttpRequestFactoryBuilder builder,
      @Nullable ProxySupport proxySupport, boolean proxyActive, boolean sslValidationDisabled,
      Optional<java.util.concurrent.Executor> virtualThreadsExecutor,
      Optional<Version> httpProtocolVersion, Optional<Consumer<?>> httpClientBuilderConsumer) {
    var b = builder.withHttpClientCustomizer(client -> {
      if (proxyActive) {
        // the flag is whether the connection to the proxy itself is TLS, not whether the proxy
        // requires credentials (Proxy-Authorization is set on requests by the request factory)
        final var secure = "https".equalsIgnoreCase(proxySupport.getProtocol());
        final var httpProxy = new HttpProxy(
            new Origin.Address(proxySupport.getHostname().get(), proxySupport.getPort()), secure);
        client.getProxyConfiguration().addProxy(httpProxy);
        if (StringUtils.hasText(proxySupport.getUsername())
            && StringUtils.hasText(proxySupport.getPassword())) {
          // Answers the proxy's 407 challenges, including on the CONNECT request which tunnels
          // https:// targets (a Proxy-Authorization header on the request itself never gets there)
          client.getAuthenticationStore()
              .addAuthentication(new BasicAuthentication(httpProxy.getURI(),
                  Authentication.ANY_REALM, proxySupport.getUsername(),
                  proxySupport.getPassword()));
        }
      }
      if (sslValidationDisabled) {
        client.setSslContextFactory(new SslContextFactory.Client(true));
      }
      virtualThreadsExecutor.ifPresent(client::setExecutor);
      httpClientBuilderConsumer.ifPresent(
          c -> ((Consumer<org.eclipse.jetty.client.HttpClient>) (Consumer<?>) c).accept(client));
    });
    if (httpProtocolVersion.isPresent()) {
      final var version = httpProtocolVersion.get();
      b = b.withHttpClientTransportFactory(connector -> switch (version) {
        case HTTP_1_1 -> new HttpClientTransportOverHTTP(connector);
        case HTTP_2 -> {
          try {
            yield new HttpClientTransportOverHTTP2(new HTTP2Client(connector));
          } catch (NoClassDefFoundError e) {
            throw new RestMisconfigurationException(
                "http-protocol-version HTTP_2 with the Jetty implementation requires org.eclipse.jetty.http2:jetty-http2-client and jetty-http2-client-transport on the class-path");
          }
        }
      });
    }
    return b;
  }
}
