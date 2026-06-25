package com.c4_soft.springaddons.rest.synchronised;

import java.time.Duration;
import java.util.concurrent.Executor;
import org.eclipse.jetty.client.HttpProxy;
import org.eclipse.jetty.client.Origin;
import org.eclipse.jetty.client.transport.HttpClientTransportOverHTTP;
import org.eclipse.jetty.http2.client.HTTP2Client;
import org.eclipse.jetty.http2.client.transport.HttpClientTransportOverHTTP2;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.springframework.http.client.JettyClientHttpRequestFactory;
import org.springframework.util.StringUtils;
import org.jspecify.annotations.Nullable;
import com.c4_soft.springaddons.rest.ProxySupport;
import com.c4_soft.springaddons.rest.RestMisconfigurationException;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;

class JettyClientHttpRequestFactoryHelper {
  public static JettyClientHttpRequestFactory get(ProxySupport proxySupport,
      ClientHttpRequestFactoryProperties properties, @Nullable Executor executor,
      @Nullable Object requestFactoryCustomizer) {
    final var httpClient = properties.getHttpProtocolVersion()
        .map(JettyClientHttpRequestFactoryHelper::httpClientForVersion)
        .orElseGet(org.eclipse.jetty.client.HttpClient::new);

    if (executor != null) {
      httpClient.setExecutor(executor);
    }

    if (proxySupport != null && proxySupport.isEnabled()) {
      final var httpProxy = new HttpProxy(
          new Origin.Address(proxySupport.getHostname().get(), proxySupport.getPort()),
          StringUtils.hasText(proxySupport.getPassword()));
      httpClient.getProxyConfiguration().addProxy(httpProxy);
    }

    if (!properties.isSslCertificatesValidationEnabled()) {
      httpClient.setSslContextFactory(new SslContextFactory.Client(true));
    }

    HttpClientCustomizer.apply(requestFactoryCustomizer, httpClient);

    final var clientHttpRequestFactory = new JettyClientHttpRequestFactory(httpClient);
    properties.getReadTimeoutMillis().map(Duration::ofMillis)
        .ifPresent(clientHttpRequestFactory::setReadTimeout);

    return clientHttpRequestFactory;
  }

  private static org.eclipse.jetty.client.HttpClient httpClientForVersion(
      java.net.http.HttpClient.Version version) {
    return switch (version) {
      case HTTP_1_1 -> new org.eclipse.jetty.client.HttpClient(new HttpClientTransportOverHTTP());
      case HTTP_2 -> {
        try {
          yield new org.eclipse.jetty.client.HttpClient(
              new HttpClientTransportOverHTTP2(new HTTP2Client()));
        } catch (NoClassDefFoundError e) {
          throw new RestMisconfigurationException(
              "http-protocol-version HTTP_2 with the Jetty implementation requires org.eclipse.jetty.http2:jetty-http2-client and jetty-http2-client-transport on the class-path");
        }
      }
    };
  }
}
