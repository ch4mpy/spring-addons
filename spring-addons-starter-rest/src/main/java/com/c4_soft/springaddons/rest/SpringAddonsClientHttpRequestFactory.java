package com.c4_soft.springaddons.rest;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;

/**
 * <p>
 * A wrapper around {@link SimpleClientHttpRequestFactory} that sends the request through an HTTP or
 * SOCKS proxy when it is enabled and when the request URI does not match the NO_PROXY pattern.
 * </p>
 * <p>
 * When going through a proxy, the Proxy-Authorization header is set if username and password are
 * non-empty.
 * </p>
 * 
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class SpringAddonsClientHttpRequestFactory implements ClientHttpRequestFactory {
  private final Optional<Pattern> nonProxyHostsPattern;
  private final ClientHttpRequestFactory proxyDelegate;
  private final ClientHttpRequestFactory noProxyDelegate;

  public SpringAddonsClientHttpRequestFactory(SystemProxyProperties systemProperties,
      ClientHttpRequestFactoryProperties addonsProperties) {
    final var proxySupport = new ProxySupport(systemProperties, addonsProperties.getProxy());

    this.nonProxyHostsPattern = proxySupport.isEnabled()
        ? Optional.ofNullable(proxySupport.getNoProxy()).map(Pattern::compile)
        : Optional.empty();

    this.noProxyDelegate = from(addonsProperties);

    if (proxySupport.isEnabled()) {
      this.proxyDelegate = new ProxyAwareClientHttpRequestFactory(proxySupport, addonsProperties);
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

  public static class ProxyAwareClientHttpRequestFactory implements ClientHttpRequestFactory {
    private final SimpleClientHttpRequestFactory delegate;
    private final @Nullable String username;
    private final @Nullable String password;

    public ProxyAwareClientHttpRequestFactory(ProxySupport proxySupport,
        ClientHttpRequestFactoryProperties properties) {
      this.username = proxySupport.getUsername();
      this.password = proxySupport.getPassword();
      this.delegate = SpringAddonsClientHttpRequestFactory.from(properties);
      final var address =
          new InetSocketAddress(proxySupport.getHostname().get(), proxySupport.getPort());
      final var proxy = new Proxy(protocolToProxyType(proxySupport.getProtocol()), address);
      this.delegate.setProxy(proxy);
    }

    @SuppressWarnings("null")
    @Override
    public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
      final var request = delegate.createRequest(uri, httpMethod);
      if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
        final var base64 = Base64.getEncoder()
            .encodeToString((username + ':' + password).getBytes(StandardCharsets.UTF_8));
        request.getHeaders().set(HttpHeaders.PROXY_AUTHORIZATION, "Basic %s".formatted(base64));
      }
      return request;
    }
  }

}
