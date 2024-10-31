package com.c4_soft.springaddons.rest;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.lang.NonNull;

/**
 * An HTTP and SOCKS proxy aware extension of {@link SimpleClientHttpRequestFactory}
 * 
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
class SpringAddonsClientHttpRequestFactory extends SimpleClientHttpRequestFactory {
  private final Optional<Pattern> nonProxyHostsPattern;
  private final Optional<Proxy> proxyOpt;

  public SpringAddonsClientHttpRequestFactory(ProxySupport proxySupport) {
    super();
    this.nonProxyHostsPattern =
        Optional.ofNullable(proxySupport.getNoProxy()).map(Pattern::compile);

    this.proxyOpt = proxySupport.getHostname().map(proxyHostname -> {
      final var address = new InetSocketAddress(proxyHostname, proxySupport.getPort());
      return new Proxy(protocolToProxyType(proxySupport.getProtocol()), address);
    });

    setConnectTimeout(proxySupport.getConnectTimeoutMillis());
  }

  @Override
  public @NonNull ClientHttpRequest createRequest(@NonNull URI uri, @NonNull HttpMethod httpMethod)
      throws IOException {
    super.setProxy(proxyOpt.filter(proxy -> {
      return nonProxyHostsPattern.map(pattern -> !pattern.matcher(uri.getHost()).matches())
          .orElse(true);
    }).orElse(null));
    return super.createRequest(uri, httpMethod);
  }

  static Proxy.Type protocolToProxyType(String protocol) {
    if (protocol == null) {
      return null;
    }
    final var lower = protocol.toLowerCase();
    if (lower.startsWith("http")) {
      return Proxy.Type.HTTP;
    }
    if (lower.startsWith("socks")) {
      return Proxy.Type.SOCKS;
    }
    return null;
  }

}
