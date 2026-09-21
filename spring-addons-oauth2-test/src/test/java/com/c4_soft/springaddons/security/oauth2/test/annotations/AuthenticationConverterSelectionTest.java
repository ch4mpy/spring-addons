package com.c4_soft.springaddons.security.oauth2.test.annotations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenAuthenticationConverter;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import com.c4_soft.springaddons.security.oauth2.test.AuthenticationFactoriesTestConf;
import reactor.core.publisher.Mono;

/**
 * Which authentication converter bean the test annotations run when several are defined (issue
 * #181): the one named by {@code authenticationConverterBeanName}, else the {@code @Primary} one,
 * else the one named like the bean spring-addons-starter-oidc auto-configures, else an error.
 */
class AuthenticationConverterSelectionTest {

  static List<String> authorities(Authentication auth) {
    return auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
  }

  static Converter<Jwt, JwtAuthenticationToken> jwtConverter(String marker) {
    return jwt -> new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority(marker)));
  }

  static OpaqueTokenAuthenticationConverter opaqueTokenConverter(String marker) {
    return (token, principal) -> new BearerTokenAuthentication(principal,
        accessToken(token), List.of(new SimpleGrantedAuthority(marker)));
  }

  static OAuth2AccessToken accessToken(String token) {
    return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token, null, null);
  }

  @Nested
  @ExtendWith(SpringExtension.class)
  @ContextConfiguration(classes = {TwoJwtConvertersWithoutPreference.class, AuthenticationFactoriesTestConf.class})
  class WithoutPreference {
    @Autowired
    WithJwt.AuthenticationFactory jwtAuthFactory;

    @Test
    @WithJwt(value = "ch4mp.json", authenticationConverterBeanName = "converterB")
    void givenBeanNameIsSetOnWithJwt_thenThatConverterIsUsed() {
      final var auth = SecurityContextHolder.getContext().getAuthentication();
      assertThat(authorities(auth)).containsExactly("CONVERTER_B");
    }

    @Test
    @WithMockJwtAuth(claims = @OpenIdClaims(sub = "42"),
        authenticationConverterBeanName = "converterA")
    void givenBeanNameIsSetOnWithMockJwtAuth_thenThatConverterIsUsed() {
      final var auth = SecurityContextHolder.getContext().getAuthentication();
      assertThat(authorities(auth)).containsExactly("CONVERTER_A");
    }

    @Test
    @WithJwt(value = "ch4mp.json", authenticationConverterBeanName = "reactiveConverter")
    void givenReactiveBeanNameIsSet_thenMonoIsBlocked() {
      final var auth = SecurityContextHolder.getContext().getAuthentication();
      assertThat(authorities(auth)).containsExactly("REACTIVE_CONVERTER");
    }

    @Test
    void givenNoPreference_whenBuildingAuthentication_thenFailsWithCandidatesAndHint() {
      assertThatThrownBy(() -> jwtAuthFactory.authentication(Map.of("sub", "42"), Map.of("alg", "none"), "bearer"))
          .isInstanceOf(NoUniqueBeanDefinitionException.class)
          .hasMessageContaining("converterA").hasMessageContaining("converterB")
          .hasMessageContaining("authenticationConverterBeanName")
          .hasMessageContaining("jwtAuthenticationConverter");
    }

    @Test
    void givenUnknownBeanName_whenBuildingAuthentication_thenFails() {
      assertThatThrownBy(() -> jwtAuthFactory.authentication(Map.of("sub", "42"), Map.of("alg", "none"),
          "bearer", "unknown")).isInstanceOf(NoSuchBeanDefinitionException.class);
    }
  }

  @Nested
  @ExtendWith(SpringExtension.class)
  @ContextConfiguration(classes = TwoJwtConvertersOnePrimary.class)
  class WithPrimary {
    @Test
    @WithJwt("ch4mp.json")
    void givenNoBeanName_thenPrimaryConverterIsUsed() {
      final var auth = SecurityContextHolder.getContext().getAuthentication();
      assertThat(authorities(auth)).containsExactly("PRIMARY");
    }

    @Test
    @WithJwt(value = "ch4mp.json", authenticationConverterBeanName = "converterB")
    void givenBeanName_thenItWinsOverPrimary() {
      final var auth = SecurityContextHolder.getContext().getAuthentication();
      assertThat(authorities(auth)).containsExactly("CONVERTER_B");
    }
  }

  @Nested
  @ExtendWith(SpringExtension.class)
  @ContextConfiguration(classes = TwoJwtConvertersOneWithDefaultName.class)
  class WithDefaultName {
    @Test
    @WithJwt("ch4mp.json")
    void givenNoBeanName_thenConverterWithDefaultNameIsUsed() {
      final var auth = SecurityContextHolder.getContext().getAuthentication();
      assertThat(authorities(auth)).containsExactly("DEFAULT_NAME");
    }
  }

  @Nested
  @ExtendWith(SpringExtension.class)
  @ContextConfiguration(classes = SingleJwtConverterWithAnotherName.class)
  class WithSingleCandidate {
    @Test
    @WithJwt("ch4mp.json")
    void givenNoBeanName_thenTheSingleConverterIsUsedWhateverItsName() {
      final var auth = SecurityContextHolder.getContext().getAuthentication();
      assertThat(authorities(auth)).containsExactly("ANOTHER_NAME");
    }
  }

  @Nested
  @ExtendWith(SpringExtension.class)
  @ContextConfiguration(classes = {OpaqueTokenConverters.class, AuthenticationFactoriesTestConf.class})
  class WithOpaqueTokenTests {
    @Autowired
    WithOpaqueToken.AuthenticationFactory opaqueTokenAuthFactory;

    @Test
    @WithOpaqueToken(value = "ch4mp.json", authenticationConverterBeanName = "converterB")
    void givenBeanNameIsSetOnWithOpaqueToken_thenThatConverterIsUsed() {
      final var auth = SecurityContextHolder.getContext().getAuthentication();
      assertThat(authorities(auth)).containsExactly("CONVERTER_B");
    }

    @Test
    @WithMockBearerTokenAuthentication(attributes = @OpenIdClaims(sub = "42"),
        authenticationConverterBeanName = "reactiveConverter")
    void givenReactiveBeanNameIsSetOnWithMockBearerTokenAuthentication_thenMonoIsBlocked() {
      final var auth = SecurityContextHolder.getContext().getAuthentication();
      assertThat(authorities(auth)).containsExactly("REACTIVE_CONVERTER");
    }

    @Test
    @WithOpaqueToken("ch4mp.json")
    void givenNoBeanName_thenConverterWithDefaultNameIsUsed() {
      final var auth = SecurityContextHolder.getContext().getAuthentication();
      assertThat(authorities(auth)).containsExactly("DEFAULT_NAME");
    }

    @Test
    void givenUnknownBeanName_whenBuildingAuthentication_thenFails() {
      assertThatThrownBy(
          () -> opaqueTokenAuthFactory.authentication(Map.of("sub", "42"), "bearer", "unknown"))
              .isInstanceOf(NoSuchBeanDefinitionException.class);
    }
  }

  @Configuration
  static class TwoJwtConvertersWithoutPreference {
    @Bean
    Converter<Jwt, JwtAuthenticationToken> converterA() {
      return jwtConverter("CONVERTER_A");
    }

    @Bean
    Converter<Jwt, JwtAuthenticationToken> converterB() {
      return jwtConverter("CONVERTER_B");
    }

    @Bean
    Converter<Jwt, Mono<AbstractAuthenticationToken>> reactiveConverter() {
      return jwt -> Mono.just(new JwtAuthenticationToken(jwt,
          List.of(new SimpleGrantedAuthority("REACTIVE_CONVERTER"))));
    }
  }

  @Configuration
  static class TwoJwtConvertersOnePrimary {
    @Bean
    @Primary
    Converter<Jwt, JwtAuthenticationToken> converterA() {
      return jwtConverter("PRIMARY");
    }

    @Bean
    Converter<Jwt, JwtAuthenticationToken> converterB() {
      return jwtConverter("CONVERTER_B");
    }
  }

  @Configuration
  static class TwoJwtConvertersOneWithDefaultName {
    @Bean
    Converter<Jwt, JwtAuthenticationToken> converterA() {
      return jwtConverter("CONVERTER_A");
    }

    @Bean
    Converter<Jwt, JwtAuthenticationToken> jwtAuthenticationConverter() {
      return jwtConverter("DEFAULT_NAME");
    }
  }

  @Configuration
  static class SingleJwtConverterWithAnotherName {
    @Bean
    Converter<Jwt, JwtAuthenticationToken> defaultJwtAuthenticationConverter() {
      return jwtConverter("ANOTHER_NAME");
    }
  }

  @Configuration
  static class OpaqueTokenConverters {
    @Bean
    OpaqueTokenAuthenticationConverter converterA() {
      return opaqueTokenConverter("CONVERTER_A");
    }

    @Bean
    OpaqueTokenAuthenticationConverter converterB() {
      return opaqueTokenConverter("CONVERTER_B");
    }

    @Bean
    OpaqueTokenAuthenticationConverter introspectionAuthenticationConverter() {
      return opaqueTokenConverter("DEFAULT_NAME");
    }

    @Bean
    ReactiveOpaqueTokenAuthenticationConverter reactiveConverter() {
      return (token, principal) -> Mono.just(new BearerTokenAuthentication(principal,
          accessToken(token),
          List.of(new SimpleGrantedAuthority("REACTIVE_CONVERTER"))));
    }
  }
}
