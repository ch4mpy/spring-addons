package com.c4_soft.springaddons.rest;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(classes = StubBootApplication.class)
@ActiveProfiles("minimal")
class AbstractSpringAddonsClientHttpRequestFactoryTest {
  @Autowired
  SpringAddonsClientHttpRequestFactory requestFactory;

  protected HttpURLConnection getConnection(ClientHttpRequest request) throws NoSuchFieldException,
      SecurityException, IllegalArgumentException, IllegalAccessException {
    final var connectionField = request.getClass().getDeclaredField("connection");
    connectionField.setAccessible(true);
    return (HttpURLConnection) connectionField.get(request);
  }

  protected boolean isUsingProxy(String uri) throws NoSuchFieldException, SecurityException,
      IllegalArgumentException, IllegalAccessException, IOException {
    final var connection =
        getConnection(requestFactory.createRequest(URI.create(uri), HttpMethod.GET));
    return connection.usingProxy();
  }
}
