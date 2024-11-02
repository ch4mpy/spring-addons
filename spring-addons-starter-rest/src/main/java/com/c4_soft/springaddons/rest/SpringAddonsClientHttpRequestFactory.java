package com.c4_soft.springaddons.rest;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.lang.NonNull;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;

/**
 * A wrapper around {@link SimpleClientHttpRequestFactory} that sends the request through an HTTP or
 * SOCKS proxy when it is enabled and when the request URI does not match the NO_PROXY pattern
 * 
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public class SpringAddonsClientHttpRequestFactory implements ClientHttpRequestFactory {
  private final Optional<Pattern> nonProxyHostsPattern;
  private final SimpleClientHttpRequestFactory proxyDelegate;
  private final SimpleClientHttpRequestFactory noProxyDelegate;

  public SpringAddonsClientHttpRequestFactory(SystemProxyProperties systemProperties,
      ClientHttpRequestFactoryProperties addonsProperties) {
    final var proxySupport = new ProxySupport(systemProperties, addonsProperties.getProxy());

    this.nonProxyHostsPattern = proxySupport.isEnabled()
        ? Optional.ofNullable(proxySupport.getNoProxy()).map(Pattern::compile)
        : Optional.empty();

    this.noProxyDelegate = from(addonsProperties);

    if (proxySupport.isEnabled()) {
      this.proxyDelegate = from(addonsProperties);
      final var address =
          new InetSocketAddress(proxySupport.getHostname().get(), proxySupport.getPort());
      final var proxy = new Proxy(protocolToProxyType(proxySupport.getProtocol()), address);
      this.proxyDelegate.setProxy(proxy);
    } else {
      this.proxyDelegate = this.noProxyDelegate;
    }
  }

  @Override
  public @NonNull ClientHttpRequest createRequest(@NonNull URI uri, @NonNull HttpMethod httpMethod)
      throws IOException {
    final var delegate = nonProxyHostsPattern.filter(pattern -> {
      final var matcher = pattern.matcher(uri.getHost());
      return matcher.matches();
    }).map(isNoProxy -> {
      return noProxyDelegate;
    }).orElse(proxyDelegate);

    return delegate.createRequest(uri, httpMethod);
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

  private static SimpleClientHttpRequestFactory from(
      ClientHttpRequestFactoryProperties properties) {
    final var requestFactory = new SimpleClientHttpRequestFactory();
    properties.getConnectTimeoutMillis().ifPresent(requestFactory::setConnectTimeout);
    properties.getReadTimeoutMillis().ifPresent(requestFactory::setReadTimeout);
    properties.getChunkSize().ifPresent(requestFactory::setChunkSize);
    return requestFactory;
  }

}
