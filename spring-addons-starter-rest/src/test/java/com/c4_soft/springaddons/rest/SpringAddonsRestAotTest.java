package com.c4_soft.springaddons.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.aot.test.generate.TestGenerationContext;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.web.context.reactive.GenericReactiveWebApplicationContext;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.annotation.AnnotationConfigUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.aot.ApplicationContextAotGenerator;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.test.tools.CompileWithForkedClassLoader;
import org.springframework.core.test.tools.TestCompiler;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.context.support.GenericWebApplicationContext;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

/**
 * The REST clients survive Spring AOT processing (gh-341): the application context is processed
 * ahead of time as {@code spring-boot:process-aot} does, then a new context is started from the
 * compiled generated code, and its clients send requests to their configured base URL.
 */
@CompileWithForkedClassLoader
public class SpringAddonsRestAotTest {

  private static final String BASE_URL = "https://aot.example.com";

  @Test
  void givenServletApplicationWithRestClientsAndWebClient_whenAotProcessed_thenGeneratedContextProvidesWorkingClients() {
    final var servletProperties = Map.<String, Object>of(
        "com.c4-soft.springaddons.rest.client.foo-client.base-url", BASE_URL,
        "com.c4-soft.springaddons.rest.client.bar-client.base-url", BASE_URL,
        "com.c4-soft.springaddons.rest.client.bar-client.expose-builder", "true",
        "com.c4-soft.springaddons.rest.client.baz-client.base-url", BASE_URL,
        "com.c4-soft.springaddons.rest.client.baz-client.type", "web-client");

    processAheadOfTimeAndRun(
        () -> new GenericWebApplicationContext(new MockServletContext()), servletProperties,
        ServletConfiguration.class, context -> {
          final var requested = context.getBean(RequestedUri.class);

          assertThatThrownBy(() -> context.getBean("fooClient", RestClient.class).get()
              .uri("/foo").retrieve().toBodilessEntity())
                  .isInstanceOf(HttpClientErrorException.class);
          assertThat(requested.get()).isEqualTo(URI.create(BASE_URL + "/foo"));

          assertThatThrownBy(() -> context.getBean("barClientBuilder", RestClient.Builder.class)
              .build().get().uri("/bar").retrieve().toBodilessEntity())
                  .isInstanceOf(HttpClientErrorException.class);
          assertThat(requested.get()).isEqualTo(URI.create(BASE_URL + "/bar"));

          assertThatThrownBy(() -> context.getBean("bazClient", WebClient.class).get()
              .uri("/baz").retrieve().toBodilessEntity().block())
                  .isInstanceOf(WebClientResponseException.class);
          assertThat(requested.get()).isEqualTo(URI.create(BASE_URL + "/baz"));
        });
  }

  @Test
  void givenReactiveApplicationWithWebClient_whenAotProcessed_thenGeneratedContextProvidesWorkingClient() {
    final var reactiveProperties =
        Map.<String, Object>of("com.c4-soft.springaddons.rest.client.qux-client.base-url", BASE_URL);

    processAheadOfTimeAndRun(GenericReactiveWebApplicationContext::new, reactiveProperties,
        ReactiveConfiguration.class, context -> {
          final var requested = context.getBean(RequestedUri.class);

          assertThatThrownBy(() -> context.getBean("quxClient", WebClient.class).get()
              .uri("/qux").retrieve().toBodilessEntity().block())
                  .isInstanceOf(WebClientResponseException.class);
          assertThat(requested.get()).isEqualTo(URI.create(BASE_URL + "/qux"));
        });
  }

  @SuppressWarnings("unchecked")
  private static void processAheadOfTimeAndRun(Supplier<GenericApplicationContext> contextFactory,
      Map<String, Object> properties, Class<?> configuration,
      Consumer<GenericApplicationContext> assertions) {
    final var aotContext = withProperties(contextFactory.get(), properties);
    AnnotationConfigUtils.registerAnnotationConfigProcessors(aotContext);
    aotContext.registerBean(configuration);
    final var generationContext = new TestGenerationContext();
    final var initializerClassName =
        new ApplicationContextAotGenerator().processAheadOfTime(aotContext, generationContext);
    generationContext.writeGeneratedContent();

    TestCompiler.forSystem().with(generationContext).compile(compiled -> {
      final var runtimeContext = withProperties(contextFactory.get(), properties);
      compiled
          .getInstance(ApplicationContextInitializer.class, initializerClassName.reflectionName())
          .initialize(runtimeContext);
      runtimeContext.refresh();
      try {
        assertions.accept(runtimeContext);
      } finally {
        runtimeContext.close();
      }
    });
  }

  private static GenericApplicationContext withProperties(GenericApplicationContext context,
      Map<String, Object> properties) {
    // as SpringApplication does: a definition registered twice fails instead of being replaced
    context.setAllowBeanDefinitionOverriding(false);
    context.getEnvironment().getPropertySources()
        .addFirst(new MapPropertySource("rest-clients", properties));
    return context;
  }

  /** The URI of the last request, which the client builders below answer with a 418. */
  public static class RequestedUri extends AtomicReference<URI> {
    private static final long serialVersionUID = 1L;
  }

  @Configuration(proxyBeanMethods = false)
  @EnableAutoConfiguration
  public static class ServletConfiguration {

    @Bean
    public RequestedUri requestedUri() {
      return new RequestedUri();
    }

    @Bean
    public RestClient.Builder restClientBuilder(RequestedUri requestedUri) {
      return RestClient.builder().requestInterceptor((request, body, execution) -> {
        requestedUri.set(request.getURI());
        return new MockClientHttpResponse(new byte[0], HttpStatus.I_AM_A_TEAPOT);
      });
    }

    @Bean
    public WebClient.Builder webClientBuilder(RequestedUri requestedUri) {
      return teapotWebClientBuilder(requestedUri);
    }
  }

  @Configuration(proxyBeanMethods = false)
  @EnableAutoConfiguration
  public static class ReactiveConfiguration {

    @Bean
    public RequestedUri requestedUri() {
      return new RequestedUri();
    }

    @Bean
    public WebClient.Builder webClientBuilder(RequestedUri requestedUri) {
      return teapotWebClientBuilder(requestedUri);
    }
  }

  private static WebClient.Builder teapotWebClientBuilder(RequestedUri requestedUri) {
    return WebClient.builder().exchangeFunction(request -> {
      requestedUri.set(request.url());
      return Mono.just(ClientResponse.create(HttpStatus.I_AM_A_TEAPOT).build());
    });
  }
}
