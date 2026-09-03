package com.c4_soft.springaddons.rest;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import java.net.URI;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * A {@link ClientHttpRequestFactory} bean in the application context is used only for clients
 * which declare no http property, or which explicitly opt in with prefer-context-factory. Any
 * other client gets a factory built from the properties it declares.
 */
@SpringBootTest(classes = ContextFactoryPrecedenceTest.MarkerFactoryConfiguration.class,
    properties = {"spring.main.web-application-type=servlet",
        "com.c4-soft.springaddons.rest.client.declaring-client.base-url=http://localhost:1",
        "com.c4-soft.springaddons.rest.client.declaring-client.http.read-timeout-millis=1234",
        "com.c4-soft.springaddons.rest.client.silent-client.base-url=http://localhost:1",
        "com.c4-soft.springaddons.rest.client.opting-in-client.base-url=http://localhost:1",
        "com.c4-soft.springaddons.rest.client.opting-in-client.http.read-timeout-millis=1234",
        "com.c4-soft.springaddons.rest.client.opting-in-client.http.prefer-context-factory=true"})
class ContextFactoryPrecedenceTest {

  @Autowired
  private RestClient declaringClient;

  @Autowired
  private RestClient silentClient;

  @Autowired
  private RestClient optingInClient;

  @Test
  void givenClientDeclaresHttpProperties_whenClientIsCreated_thenContextFactoryIsNotUsed() {
    assertFalse(usesContextFactory(declaringClient));
  }

  @Test
  void givenClientDeclaresNoHttpProperty_whenClientIsCreated_thenContextFactoryIsUsed() {
    assertTrue(usesContextFactory(silentClient));
  }

  @Test
  void givenClientPrefersContextFactory_whenClientIsCreated_thenContextFactoryIsUsed() {
    assertTrue(usesContextFactory(optingInClient));
  }

  private static boolean usesContextFactory(RestClient client) {
    try {
      client.get().uri("/").retrieve().toBodilessEntity();
      return false;
    } catch (Exception e) {
      final var cause = NestedExceptionUtils.getMostSpecificCause(e);
      return MarkerClientHttpRequestFactory.MARKER.equals(cause.getMessage());
    }
  }

  @Configuration
  @EnableAutoConfiguration
  static class MarkerFactoryConfiguration {

    @Bean
    ClientHttpRequestFactory markerClientHttpRequestFactory() {
      return new MarkerClientHttpRequestFactory();
    }
  }

  static class MarkerClientHttpRequestFactory implements ClientHttpRequestFactory {

    static final String MARKER = "context ClientHttpRequestFactory bean was used";

    @Override
    public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
      throw new IOException(MARKER);
    }
  }
}
