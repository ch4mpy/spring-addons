package com.c4_soft.springaddons.rest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.net.URI;
import java.net.http.HttpClient;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;
import com.c4_soft.springaddons.rest.synchronised.HttpClientCustomizer;
import com.c4_soft.springaddons.rest.synchronised.SpringAddonsClientHttpRequestFactory;

/**
 * Verifies that an {@link HttpClientCustomizer} is applied to the underlying client builder by
 * {@link SpringAddonsClientHttpRequestFactory} (JDK implementation).
 */
class SpringAddonsClientHttpRequestFactoryCustomizerTest {

  @Test
  void givenJdkCustomizer_whenCreatingRequest_thenItIsAppliedToTheHttpClient() throws Exception {
    final var http = new ClientHttpRequestFactoryProperties();
    final HttpClientCustomizer<HttpClient.Builder> customizer =
        builder -> builder.version(HttpClient.Version.HTTP_1_1);

    final var factory = new SpringAddonsClientHttpRequestFactory(new SystemProxyProperties(), http,
        null, customizer);

    assertEquals(HttpClient.Version.HTTP_1_1, jdkHttpClientOf(factory).version());
  }

  @Test
  void givenNoCustomizer_whenCreatingRequest_thenTheJdkDefaultIsKept() throws Exception {
    final var http = new ClientHttpRequestFactoryProperties();

    final var factory =
        new SpringAddonsClientHttpRequestFactory(new SystemProxyProperties(), http, null, null);

    assertEquals(HttpClient.Version.HTTP_2, jdkHttpClientOf(factory).version());
  }

  private static HttpClient jdkHttpClientOf(SpringAddonsClientHttpRequestFactory factory)
      throws Exception {
    final ClientHttpRequest request =
        factory.createRequest(URI.create("https://localhost/test"), HttpMethod.GET);
    final var httpClientField = request.getClass().getDeclaredField("httpClient");
    httpClientField.setAccessible(true);
    return (HttpClient) httpClientField.get(request);
  }
}
