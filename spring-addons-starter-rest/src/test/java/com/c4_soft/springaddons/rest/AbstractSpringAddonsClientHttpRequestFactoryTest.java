package com.c4_soft.springaddons.rest;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.test.context.ActiveProfiles;
import com.c4_soft.springaddons.rest.synchronised.SpringAddonsClientHttpRequestFactory;

@SpringBootTest(classes = StubBootApplication.class)
@ActiveProfiles("minimal")
class AbstractSpringAddonsClientHttpRequestFactoryTest {
  @Autowired
  SpringAddonsClientHttpRequestFactory requestFactory;

  protected HttpClient getConnection(ClientHttpRequest request) throws NoSuchFieldException,
      SecurityException, IllegalArgumentException, IllegalAccessException {
    final var connectionField = request.getClass().getDeclaredField("httpClient");
    connectionField.setAccessible(true);
    return (HttpClient) connectionField.get(request);
  }

  protected boolean isUsingProxy(String uri) throws NoSuchFieldException, SecurityException,
      IllegalArgumentException, IllegalAccessException, IOException {
    final var httpClient =
        getConnection(requestFactory.createRequest(URI.create(uri), HttpMethod.GET));
    return httpClient.proxy().isPresent();
  }
}
