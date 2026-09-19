package com.c4_soft.springaddons.samples.resourceserver.greetings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithAnonymousUser;
import com.c4_soft.springaddons.samples.resourceserver.SecurityConfig;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AddonsWebmvcComponentTest;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidToken;

/**
 * Method security on a {@code @Service}, tested without any HTTP request: {@code spring-security-test}
 * request post-processors need {@code MockMvc}, annotations don't. The test context holds only the
 * security configuration and the tested component.
 */
@AddonsWebmvcComponentTest
@SpringBootTest(classes = {SecurityConfig.class, GreetingsService.class})
class GreetingsServiceTest {

  @Autowired
  GreetingsService greetingsService;

  @Test
  @WithAnonymousUser
  void givenUserIsAnonymous_whenGreet_thenDenied() {
    assertThatThrownBy(() -> greetingsService.greet(null))
        .isInstanceOf(AuthorizationDeniedException.class);
  }

  @Test
  @WithJwt("brice.json")
  void givenUserIsBrice_whenGreet_thenGreetingUsesTheClaims() {
    final var auth = currentAuthentication();

    assertThat(greetingsService.greet(auth).message())
        .isEqualTo("Hi Brice! You are granted with [NICE, default-roles-spring-addons, offline_access, uma_authorization].");
  }

  @Test
  @WithJwt("brice.json")
  void givenUserIsBrice_whenNice_thenGreeted() {
    assertThat(greetingsService.nice(currentAuthentication()).message())
        .isEqualTo("Dear brice, glad to see you!");
  }

  @Test
  @WithJwt("igor.json")
  void givenUserIsIgor_whenNice_thenDenied() {
    final var auth = currentAuthentication();

    assertThatThrownBy(() -> greetingsService.nice(auth))
        .isInstanceOf(AuthorizationDeniedException.class);
  }

  @SuppressWarnings("unchecked")
  private static OAuthentication<OpenidToken> currentAuthentication() {
    return (OAuthentication<OpenidToken>) SecurityContextHolder.getContext().getAuthentication();
  }
}
