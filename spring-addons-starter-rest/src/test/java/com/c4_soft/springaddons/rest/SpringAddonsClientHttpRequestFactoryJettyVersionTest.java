package com.c4_soft.springaddons.rest;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.net.http.HttpClient;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import com.c4_soft.springaddons.rest.RestMisconfigurationException;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties.ClientHttpRequestFactoryImpl;
import com.c4_soft.springaddons.rest.synchronised.SpringAddonsClientHttpRequestFactory;

/**
 * Verifies the {@code http.http-protocol-version} mapping for the Jetty implementation: HTTP/1.1 is
 * configured through the over-HTTP transport, HTTP/2 fails fast (it requires jetty-http2-client).
 */
class SpringAddonsClientHttpRequestFactoryJettyVersionTest {

  @Test
  void givenJettyAndHttp1_1_whenBuildingFactory_thenSucceeds() {
    final var http = new ClientHttpRequestFactoryProperties();
    http.setClientHttpRequestFactoryImpl(ClientHttpRequestFactoryImpl.JETTY);
    http.setHttpProtocolVersion(Optional.of(HttpClient.Version.HTTP_1_1));

    assertDoesNotThrow(
        () -> new SpringAddonsClientHttpRequestFactory(new SystemProxyProperties(), http));
  }

  @Test
  void givenJettyAndHttp2_whenBuildingFactory_thenThrows() {
    final var http = new ClientHttpRequestFactoryProperties();
    http.setClientHttpRequestFactoryImpl(ClientHttpRequestFactoryImpl.JETTY);
    http.setHttpProtocolVersion(Optional.of(HttpClient.Version.HTTP_2));

    assertThrows(RestMisconfigurationException.class,
        () -> new SpringAddonsClientHttpRequestFactory(new SystemProxyProperties(), http));
  }
}
