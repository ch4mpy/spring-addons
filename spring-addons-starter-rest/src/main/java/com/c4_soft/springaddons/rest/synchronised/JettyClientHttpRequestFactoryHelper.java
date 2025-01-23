package com.c4_soft.springaddons.rest.synchronised;

import java.time.Duration;
import org.eclipse.jetty.client.HttpProxy;
import org.eclipse.jetty.client.Origin;
import org.springframework.http.client.JettyClientHttpRequestFactory;
import org.springframework.util.StringUtils;
import com.c4_soft.springaddons.rest.ProxySupport;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;

class JettyClientHttpRequestFactoryHelper {
  static JettyClientHttpRequestFactory get(ProxySupport proxySupport,
      ClientHttpRequestFactoryProperties properties) {
    final var httpClient = new org.eclipse.jetty.client.HttpClient();

    if (proxySupport != null && proxySupport.isEnabled()) {
      final var httpProxy = new HttpProxy(
          new Origin.Address(proxySupport.getHostname().get(), proxySupport.getPort()),
          StringUtils.hasText(proxySupport.getPassword()));
      httpClient.getProxyConfiguration().addProxy(httpProxy);
    }
    final var clientHttpRequestFactory = new JettyClientHttpRequestFactory(httpClient);
    properties.getReadTimeoutMillis().map(Duration::ofMillis)
        .ifPresent(clientHttpRequestFactory::setReadTimeout);
    return clientHttpRequestFactory;
  }

}
