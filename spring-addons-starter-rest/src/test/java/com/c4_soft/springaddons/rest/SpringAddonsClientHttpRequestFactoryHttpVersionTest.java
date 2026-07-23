package com.c4_soft.springaddons.rest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.net.URI;
import java.net.http.HttpClient;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;
import com.c4_soft.springaddons.rest.synchronised.SpringAddonsClientHttpRequestFactory;

/**
 * Verifies that the optional {@code http.http-protocol-version} property is applied to the JDK
 * {@link HttpClient} built by {@link SpringAddonsClientHttpRequestFactory}.
 */
class SpringAddonsClientHttpRequestFactoryHttpVersionTest {

  @Test
  void givenHttpProtocolVersionIsSet_whenCreatingRequest_thenJdkHttpClientUsesIt()
      throws Exception {
    final var http = new ClientHttpRequestFactoryProperties();
    http.setHttpProtocolVersion(Optional.of(HttpClient.Version.HTTP_1_1));

    final var httpClient = jdkHttpClientFor(http);

    assertEquals(HttpClient.Version.HTTP_1_1, httpClient.version());
  }

  @Test
  void givenHttpProtocolVersionIsNotSet_whenCreatingRequest_thenJdkHttpClientUsesItsDefault()
      throws Exception {
    final var http = new ClientHttpRequestFactoryProperties();

    final var httpClient = jdkHttpClientFor(http);

    // The JDK HttpClient defaults to HTTP/2 when no version is configured.
    assertEquals(HttpClient.Version.HTTP_2, httpClient.version());
  }

  private static HttpClient jdkHttpClientFor(ClientHttpRequestFactoryProperties http)
      throws Exception {
    final var factory = new SpringAddonsClientHttpRequestFactory(new SystemProxyProperties(), http);
    final ClientHttpRequest request =
        factory.createRequest(URI.create("https://localhost/test"), HttpMethod.GET);
    final var httpClientField = request.getClass().getDeclaredField("httpClient");
    httpClientField.setAccessible(true);
    return (HttpClient) httpClientField.get(request);
  }
}
