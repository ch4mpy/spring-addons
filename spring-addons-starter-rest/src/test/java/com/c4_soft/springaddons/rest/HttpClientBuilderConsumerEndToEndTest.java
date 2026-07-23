package com.c4_soft.springaddons.rest;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

/**
 * End-to-end check of the http-client-builder-consumer-bean property: the named {@link Consumer}
 * bean is resolved from the application context and applied to the implementation-specific client
 * builder for each client-http-request-factory-impl.
 */
@SpringBootTest(
    classes = HttpClientBuilderConsumerEndToEndTest.ConsumersConfiguration.class,
    properties = {"spring.main.web-application-type=servlet",
        "spring.autoconfigure.exclude=org.springframework.boot.http.client.autoconfigure.imperative.ImperativeHttpClientAutoConfiguration",
        "com.c4-soft.springaddons.rest.client.foo-client.base-url=http://localhost:1",
        "com.c4-soft.springaddons.rest.client.bar-client.base-url=http://localhost:1",
        "com.c4-soft.springaddons.rest.client.jdk-e2e-client.base-url=http://localhost:1",
        "com.c4-soft.springaddons.rest.client.jdk-e2e-client.http.http-client-builder-consumer-bean=jdkHttpClientBuilderConsumer",
        "com.c4-soft.springaddons.rest.client.jetty-e2e-client.base-url=http://localhost:1",
        "com.c4-soft.springaddons.rest.client.jetty-e2e-client.http.client-http-request-factory-impl=jetty",
        "com.c4-soft.springaddons.rest.client.jetty-e2e-client.http.http-client-builder-consumer-bean=jettyHttpClientBuilderConsumer",
        "com.c4-soft.springaddons.rest.client.hc-e2e-client.base-url=http://localhost:1",
        "com.c4-soft.springaddons.rest.client.hc-e2e-client.http.client-http-request-factory-impl=http-components",
        "com.c4-soft.springaddons.rest.client.hc-e2e-client.http.http-client-builder-consumer-bean=httpComponentsHttpClientBuilderConsumer"})
class HttpClientBuilderConsumerEndToEndTest {

  @Autowired
  private RestClient jdkE2eClient;

  @Autowired
  private RestClient jettyE2eClient;

  @Autowired
  private RestClient hcE2eClient;

  @Autowired
  private RestClient fooClient;

  @Test
  void givenConsumerBeanNames_whenRestClientsAreCreated_thenEachConsumerIsAppliedToItsBuilder() {
    assertNotNull(jdkE2eClient);
    assertNotNull(jettyE2eClient);
    assertNotNull(hcE2eClient);

    assertFalse(ConsumersConfiguration.jdkSeen.isEmpty());
    assertInstanceOf(java.net.http.HttpClient.Builder.class, ConsumersConfiguration.jdkSeen.get(0));

    assertFalse(ConsumersConfiguration.jettySeen.isEmpty());
    assertInstanceOf(org.eclipse.jetty.client.HttpClient.class,
        ConsumersConfiguration.jettySeen.get(0));

    assertFalse(ConsumersConfiguration.hcSeen.isEmpty());
    assertInstanceOf(org.apache.hc.client5.http.impl.classic.HttpClientBuilder.class,
        ConsumersConfiguration.hcSeen.get(0));
  }

  @Test
  void givenNoConsumerBeanName_whenRestClientIsCreated_thenNoConsumerIsApplied() {
    assertNotNull(fooClient);
    assertTrue(ConsumersConfiguration.fooSeen.isEmpty());
  }

  @Configuration
  @EnableAutoConfiguration
  static class ConsumersConfiguration {
    static final List<Object> jdkSeen = new CopyOnWriteArrayList<>();
    static final List<Object> jettySeen = new CopyOnWriteArrayList<>();
    static final List<Object> hcSeen = new CopyOnWriteArrayList<>();
    static final List<Object> fooSeen = new CopyOnWriteArrayList<>();

    @Bean
    Consumer<java.net.http.HttpClient.Builder> jdkHttpClientBuilderConsumer() {
      return jdkSeen::add;
    }

    @Bean
    Consumer<org.eclipse.jetty.client.HttpClient> jettyHttpClientBuilderConsumer() {
      return jettySeen::add;
    }

    @Bean
    Consumer<org.apache.hc.client5.http.impl.classic.HttpClientBuilder> httpComponentsHttpClientBuilderConsumer() {
      return hcSeen::add;
    }

    @Bean
    Consumer<Object> unusedConsumer() {
      return fooSeen::add;
    }
  }
}
