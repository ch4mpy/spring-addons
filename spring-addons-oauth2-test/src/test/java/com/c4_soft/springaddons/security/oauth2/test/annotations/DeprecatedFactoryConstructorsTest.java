package com.c4_soft.springaddons.security.oauth2.test.annotations;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenAuthenticationConverter;
import reactor.core.publisher.Mono;

/**
 * The constructors taking the converters themselves (kept for backward compatibility on the 8.x
 * line) behave as they used to: the servlet converter is used when given, else the reactive one,
 * else the default authentication.
 */
@SuppressWarnings("deprecation")
class DeprecatedFactoryConstructorsTest {

  static List<String> authorities(Authentication auth) {
    return auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
  }

  @Test
  void givenServletAndReactiveJwtConverters_whenBuildingAuthentication_thenServletOneIsUsed() {
    final var factory = new WithJwt.AuthenticationFactory(
        Optional.of(AuthenticationConverterSelectionTest.jwtConverter("SERVLET")),
        Optional.of(jwt -> Mono.just(new JwtAuthenticationToken(jwt,
            List.of(new SimpleGrantedAuthority("REACTIVE"))))));

    final var auth =
        factory.authentication(Map.of("sub", "ch4mp"), Map.of("alg", "none"), "machin.truc.chose");

    assertThat(authorities(auth)).containsExactly("SERVLET");
  }

  @Test
  void givenOnlyReactiveJwtConverter_whenBuildingAuthentication_thenItIsUsed() {
    final var factory = new WithJwt.AuthenticationFactory(Optional.empty(),
        Optional.of(jwt -> Mono.just(new JwtAuthenticationToken(jwt,
            List.of(new SimpleGrantedAuthority("REACTIVE"))))));

    final var auth =
        factory.authentication(Map.of("sub", "ch4mp"), Map.of("alg", "none"), "machin.truc.chose");

    assertThat(authorities(auth)).containsExactly("REACTIVE");
  }

  @Test
  void givenNoOpaqueTokenConverter_whenBuildingAuthentication_thenDefaultIsUsed() {
    final var factory =
        new WithOpaqueToken.AuthenticationFactory(Optional.empty(), Optional.empty());

    final var auth = factory.authentication(Map.of("username", "ch4mp"), "machin.truc.chose");

    // the default BearerTokenAuthentication carries the claims as principal attributes
    assertThat(auth).isInstanceOf(BearerTokenAuthentication.class);
    assertThat(((BearerTokenAuthentication) auth).getTokenAttributes()).containsEntry("username",
        "ch4mp");
  }

  @Test
  void givenReactiveOpaqueTokenConverter_whenBuildingAuthentication_thenMonoIsBlocked() {
    final ReactiveOpaqueTokenAuthenticationConverter reactive = (token, principal) -> Mono
        .just(AuthenticationConverterSelectionTest.opaqueTokenConverter("REACTIVE").convert(token,
            principal));
    final var factory =
        new WithOpaqueToken.AuthenticationFactory(Optional.empty(), Optional.of(reactive));

    final var auth = factory.authentication(Map.of("sub", "ch4mp"), "machin.truc.chose");

    assertThat(authorities(auth)).containsExactly("REACTIVE");
  }
}
