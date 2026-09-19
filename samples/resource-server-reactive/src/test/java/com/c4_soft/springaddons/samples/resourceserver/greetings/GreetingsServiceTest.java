package com.c4_soft.springaddons.samples.resourceserver.greetings;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.WithAnonymousUser;
import com.c4_soft.springaddons.samples.resourceserver.ResourceServerReactiveApplication;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AddonsWebfluxComponentTest;
import reactor.test.StepVerifier;

/**
 * Reactive method security on a {@code @Service}, tested without any HTTP request. The test
 * security context set by the annotations is propagated to the Reactor context.
 */
@AddonsWebfluxComponentTest
@SpringBootTest(classes = {ResourceServerReactiveApplication.class, GreetingsService.class})
class GreetingsServiceTest {

  @Autowired
  GreetingsService greetingsService;

  @Test
  @WithAnonymousUser
  void givenUserIsAnonymous_whenGreet_thenDenied() {
    StepVerifier.create(greetingsService.greet(null))
        .expectError(AuthorizationDeniedException.class).verify();
  }

  @Test
  @WithJwt("brice.json")
  void givenUserIsBrice_whenGreet_thenGreetingUsesTheClaims() {
    StepVerifier.create(greetingsService.greet(currentAuthentication()))
        .assertNext(greeting -> assertThat(greeting.message()).isEqualTo(
            "Hi Brice! You are granted with [NICE, default-roles-spring-addons, offline_access, uma_authorization]."))
        .verifyComplete();
  }

  @Test
  @WithJwt("brice.json")
  void givenUserIsBrice_whenNice_thenGreeted() {
    StepVerifier.create(greetingsService.nice(currentAuthentication()))
        .assertNext(
            greeting -> assertThat(greeting.message()).isEqualTo("Dear brice, glad to see you!"))
        .verifyComplete();
  }

  @Test
  @WithJwt("igor.json")
  void givenUserIsIgor_whenNice_thenDenied() {
    StepVerifier.create(greetingsService.nice(currentAuthentication()))
        .expectError(AuthorizationDeniedException.class).verify();
  }

  private static JwtAuthenticationToken currentAuthentication() {
    return (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
  }
}
