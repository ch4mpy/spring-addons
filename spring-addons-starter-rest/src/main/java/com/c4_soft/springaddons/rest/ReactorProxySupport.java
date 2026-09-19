package com.c4_soft.springaddons.rest;

import reactor.netty.http.client.HttpClient;
import reactor.netty.transport.ProxyProvider;

/**
 * <p>
 * Configures a Reactor Netty {@link HttpClient} proxy from a {@link ProxySupport}. Shared by the
 * WebClient connector and the Reactor {@code ClientHttpRequestFactory} customizations.
 * </p>
 * <p>
 * Isolates every reference to reactor-netty types (an optional dependency): it is loaded only when
 * a Reactor Netty based client is actually configured with a proxy.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public final class ReactorProxySupport {

  private ReactorProxySupport() {}

  /**
   * @param client the client to configure
   * @param proxySupport the (enabled) proxy configuration
   * @return a client going through the proxy, except for {@code no_proxy} hosts
   */
  public static HttpClient withProxy(HttpClient client, ProxySupport proxySupport) {
    return client.proxy(proxy -> proxy.type(toProxyType(proxySupport.getProtocol()))
        .host(proxySupport.getHostname().orElseThrow()).port(proxySupport.getPort())
        .username(proxySupport.getUsername()).password(username -> proxySupport.getPassword())
        .nonProxyHosts(proxySupport.getNoProxy())
        .connectTimeoutMillis(proxySupport.getConnectTimeoutMillis()));
  }

  /**
   * @param protocol the proxy protocol from configuration ({@code http}, {@code https},
   *        {@code socks4} or {@code socks5}); anything else than HTTP or SOCKS4 is SOCKS5
   * @return the Reactor Netty proxy type, HTTP if the protocol is not set
   */
  public static ProxyProvider.Proxy toProxyType(String protocol) {
    if (protocol == null) {
      return ProxyProvider.Proxy.HTTP;
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
