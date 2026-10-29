package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.registration;
import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.validContext;
import static com.c4_soft.springaddons.security.oidc.starter.synchronised.client.SingleRefreshTokenFlowOAuth2AuthorizedClientProviderTest.inParallel;
import static org.assertj.core.api.Assertions.assertThat;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import com.c4_soft.springaddons.security.oidc.starter.BlockingClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

class PerRegistrationOAuth2AuthorizedClientProviderConcurrencyTest {
  private static final int REQUESTS = 8;

  @Test
  void givenARepositoryWhichIsNotIterable_whenConcurrentFirstAuthorizations_thenTheProvidersOfTheRegistrationAreBuiltOnce()
      throws Exception {
    final var clientProperties = new BlockingClientProperties(REQUESTS);
    final var addonsProperties = new SpringAddonsOidcProperties();
    addonsProperties.setClient(clientProperties);
    final ClientRegistrationRepository notIterable = registrationId -> registration(registrationId);
    final var provider =
        new PerRegistrationOAuth2AuthorizedClientProvider(notIterable, addonsProperties);
    final var context = validContext("login", "ch4mp");

    inParallel(new CountDownLatch(1), IntStream.range(0, REQUESTS)
        .<Callable<OAuth2AuthorizedClient>>mapToObj(i -> () -> provider.authorize(context))
        .toList());

    assertThat(clientProperties.extraTokenParametersReads()).isOne();
  }
}
