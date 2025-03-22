package com.c4_soft.springaddons.rest.synchronised;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;
import com.c4_soft.springaddons.rest.ProxySupport;
import com.c4_soft.springaddons.rest.RestMisconfigurationException;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;
import com.c4_soft.springaddons.rest.SystemProxyProperties;

/**
 * <p>
 * An implementation of {@link ClientHttpRequestFactory} that sends the request through an HTTP or
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

    this.noProxyDelegate = clientHttpRequestFactory(null, addonsProperties);

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

  private static HttpClient.Builder httpClientBuilder(
      ClientHttpRequestFactoryProperties properties) {
    final var httpClient = HttpClient.newBuilder();
    properties.getConnectTimeoutMillis().map(Duration::ofMillis)
        .ifPresent(httpClient::connectTimeout);
    return httpClient;
  }

  private static ClientHttpRequestFactory clientHttpRequestFactory(ProxySupport proxySupport,
      ClientHttpRequestFactoryProperties properties) {
    switch (properties.getClientHttpRequestFactoryImpl()) {
      case HTTP_COMPONENTS:
        try {
          return HttpComponentsClientHttpRequestFactoryHelper.get(proxySupport, properties);
        } catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e) {
          throw new RestMisconfigurationException(e);
        }
      case JETTY:
        return JettyClientHttpRequestFactoryHelper.get(proxySupport, properties);
      default:
        try {
          return jdkClientHttpRequestFactory(proxySupport, properties);
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
          throw new RestMisconfigurationException(e);
        }
    }
  }

  private static JdkClientHttpRequestFactory jdkClientHttpRequestFactory(ProxySupport proxySupport,
      ClientHttpRequestFactoryProperties properties)
      throws NoSuchAlgorithmException, KeyManagementException {
    final var httpClientBuilder = httpClientBuilder(properties);
    if (proxySupport != null && proxySupport.isEnabled()) {
      final var proxyAddress =
          new InetSocketAddress(proxySupport.getHostname().get(), proxySupport.getPort());
      httpClientBuilder.proxy(ProxySelector.of(proxyAddress));
    }

    if (!properties.isSslCertificatesValidationEnabled()) {
      final var sslContext = SSLContext.getInstance("SSL");
      final var trustManager = new X509TrustManager() {
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
          return new X509Certificate[] {};
        }

        @Override
        public void checkClientTrusted(X509Certificate[] arg0, String arg1)
            throws CertificateException {}

        @Override
        public void checkServerTrusted(X509Certificate[] arg0, String arg1)
            throws CertificateException {}
      };
      sslContext.init(null, new TrustManager[] {trustManager}, new java.security.SecureRandom());

      httpClientBuilder.sslContext(sslContext);
    }

    final var clientHttpRequestFactory = new JdkClientHttpRequestFactory(httpClientBuilder.build());
    properties.getReadTimeoutMillis().map(Duration::ofMillis)
        .ifPresent(clientHttpRequestFactory::setReadTimeout);

    return clientHttpRequestFactory;
  }

  public static class ProxyAwareClientHttpRequestFactory implements ClientHttpRequestFactory {
    private final ClientHttpRequestFactory delegate;
    private final @Nullable String username;
    private final @Nullable String password;

    public ProxyAwareClientHttpRequestFactory(ProxySupport proxySupport,
        ClientHttpRequestFactoryProperties properties) {
      this.username = proxySupport.getUsername();
      this.password = proxySupport.getPassword();
      final var httpClient = HttpClient.newBuilder();
      final var proxyAddress =
          new InetSocketAddress(proxySupport.getHostname().get(), proxySupport.getPort());
      httpClient.proxy(ProxySelector.of(proxyAddress));
      properties.getConnectTimeoutMillis().map(Duration::ofMillis)
          .ifPresent(httpClient::connectTimeout);
      this.delegate = clientHttpRequestFactory(proxySupport, properties);
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
