package com.c4_soft.springaddons.rest;

import static org.junit.jupiter.api.Assertions.assertTrue;
import java.net.URI;
import java.net.http.HttpClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;
import com.c4_soft.springaddons.rest.synchronised.SpringAddonsClientHttpRequestFactory;

/**
 * Verifies that the {@code http.use-virtual-threads} property sets an executor on the JDK
 * {@link HttpClient} built by {@link SpringAddonsClientHttpRequestFactory}.
 */
class SpringAddonsClientHttpRequestFactoryVirtualThreadsTest {

  @Test
  @EnabledForJreRange(min = JRE.JAVA_21) // virtual threads require Java 21+
  void givenUseVirtualThreads_whenCreatingRequest_thenTheJdkHttpClientHasAnExecutor()
      throws Exception {
    final var http = new ClientHttpRequestFactoryProperties();
    http.setUseVirtualThreads(true);

    assertTrue(jdkHttpClientFor(http).executor().isPresent());
  }

  @Test
  void givenUseVirtualThreadsDisabled_whenCreatingRequest_thenTheJdkHttpClientHasNoExplicitExecutor()
      throws Exception {
    final var http = new ClientHttpRequestFactoryProperties();

    assertTrue(jdkHttpClientFor(http).executor().isEmpty());
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
