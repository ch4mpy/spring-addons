package com.c4_soft.springaddons.rest.synchronised;

import java.time.Duration;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.routing.DefaultProxyRoutePlanner;
import org.apache.hc.core5.http.HttpHost;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import com.c4_soft.springaddons.rest.ProxySupport;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;

class HttpComponentsClientHttpRequestFactoryHelper {

  static HttpComponentsClientHttpRequestFactory get(ProxySupport proxySupport,
      ClientHttpRequestFactoryProperties properties) {
    final var httpClientBuilder = HttpClients.custom();
    if (proxySupport != null && proxySupport.isEnabled()) {
      final var proxy = new HttpHost(proxySupport.getHostname().get(), proxySupport.getPort());
      httpClientBuilder.setRoutePlanner(new DefaultProxyRoutePlanner(proxy));
    }
    final var clientHttpRequestFactory =
        new HttpComponentsClientHttpRequestFactory(httpClientBuilder.build());
    properties.getReadTimeoutMillis().map(Duration::ofMillis)
        .ifPresent(clientHttpRequestFactory::setReadTimeout);
    return clientHttpRequestFactory;
  }

}
