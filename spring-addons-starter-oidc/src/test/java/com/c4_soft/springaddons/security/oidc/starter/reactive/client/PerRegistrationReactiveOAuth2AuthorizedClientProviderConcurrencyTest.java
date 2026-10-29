package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.registration;
import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.validContext;
import static com.c4_soft.springaddons.security.oidc.starter.reactive.client.SingleRefreshTokenFlowReactiveOAuth2AuthorizedClientProviderTest.inParallel;
import static org.assertj.core.api.Assertions.assertThat;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import com.c4_soft.springaddons.security.oidc.starter.BlockingClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

class PerRegistrationReactiveOAuth2AuthorizedClientProviderConcurrencyTest {
  private static final int REQUESTS = 8;

  @Test
  void givenARepositoryWhichIsNotIterable_whenConcurrentFirstAuthorizations_thenTheProvidersOfTheRegistrationAreBuiltOnce() {
    final var clientProperties = new BlockingClientProperties(REQUESTS);
    final var addonsProperties = new SpringAddonsOidcProperties();
    addonsProperties.setClient(clientProperties);
    final ReactiveClientRegistrationRepository notIterable =
        registrationId -> Mono.just(registration(registrationId));
    final var provider =
        new PerRegistrationReactiveOAuth2AuthorizedClientProvider(notIterable, addonsProperties);
    final var context = validContext("login", "ch4mp");

    inParallel(IntStream.range(0, REQUESTS)
        .mapToObj(i -> Mono.defer(() -> provider.authorize(context))
            .subscribeOn(Schedulers.boundedElastic()))
        .toList());

    assertThat(clientProperties.extraTokenParametersReads()).isOne();
  }
}
