package com.c4_soft.springaddons.rest.synchronised;

import javax.net.ssl.SSLException;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.http.client.ReactorClientHttpRequestFactoryBuilder;
import com.c4_soft.springaddons.rest.ProxySupport;
import com.c4_soft.springaddons.rest.RestMisconfigurationException;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import reactor.netty.transport.ProxyProvider;

/**
 * <p>
 * Isolates every reference to {@code io.projectreactor.netty:reactor-netty-http} (and Netty) types
 * so that this class is loaded (and its bytecode verified) only when a REST client is actually
 * configured with the REACTOR implementation.
 * </p>
 * <p>
 * {@link SpringAddonsClientHttpRequestFactoryMerger} must never import any reactor-netty or Netty
 * type directly: doing so would make class-loading of the merger itself fail with a
 * {@link NoClassDefFoundError} for consumers who don't have reactor-netty-http on the class-path
 * (it is typically pulled in transitively by spring-boot-starter-webflux, an optional dependency of
 * spring-addons-starter-rest), even when they never use the REACTOR implementation.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
class ReactorRequestFactoryBuilderCustomizer {

  private ReactorRequestFactoryBuilderCustomizer() {}

  static ReactorClientHttpRequestFactoryBuilder customize(
      ReactorClientHttpRequestFactoryBuilder builder, @Nullable ProxySupport proxySupport,
      boolean proxyActive, boolean sslValidationDisabled) {
    return builder.withHttpClientCustomizer(client -> {
      var c = client;
      if (proxyActive) {
        c = c.proxy(proxy -> proxy.type(protocolToProxyType(proxySupport.getProtocol()))
            .host(proxySupport.getHostname().get()).port(proxySupport.getPort())
            .username(proxySupport.getUsername()).password(username -> proxySupport.getPassword())
            .nonProxyHosts(proxySupport.getNoProxy())
            .connectTimeoutMillis(proxySupport.getConnectTimeoutMillis()));
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
  }

  private static ProxyProvider.Proxy protocolToProxyType(String protocol) {
    if (protocol == null) {
      return null;
    }
    final var lower = protocol.toLowerCase();
    if (lower.startsWith("http")) {
      return ProxyProvider.Proxy.HTTP;
    }
    if (lower.startsWith("socks4")) {
      return ProxyProvider.Proxy.SOCKS4;
    }
    return ProxyProvider.Proxy.SOCKS5;
  }
}
