package com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import java.net.URI;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.properties.NotAConfiguredOpenidProviderException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties.OpenidProviderProperties;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

@ExtendWith(MockitoExtension.class)
class JWTClaimsSetAuthenticationManagerTest {

  @Mock
  OpenidProviderPropertiesResolver opPropertiesResolver;

  @Mock
  SpringAddonsJwtDecoderFactory jwtDecoderFactory;

  @Mock
  Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter;

  @Mock
  JwtDecoder jwtDecoder;

  @Test
  void givenTokenIssuerIsNotConfigured_whenAuthenticate_thenAuthenticationExceptionIsThrown() {
    when(opPropertiesResolver.resolve(any())).thenReturn(Optional.empty());
    final var manager = new JWTClaimsSetAuthenticationManager(opPropertiesResolver,
        jwtDecoderFactory, jwtAuthenticationConverter);

    assertThatThrownBy(() -> manager.authenticate(bearer("https://unknown", "ch4mp")))
        .isInstanceOf(NotAConfiguredOpenidProviderException.class)
        .isInstanceOf(AuthenticationException.class);

    verify(jwtDecoderFactory, never()).create(any(), any(), any());
  }

  @Test
  void givenTokenHasNoIssuer_whenAuthenticate_thenInvalidBearerTokenExceptionIsThrown() {
    final var manager = new JWTClaimsSetAuthenticationManager(opPropertiesResolver,
        jwtDecoderFactory, jwtAuthenticationConverter);

    assertThatThrownBy(() -> manager.authenticate(bearer(null, "ch4mp")))
        .isInstanceOf(InvalidBearerTokenException.class);

    verify(jwtDecoderFactory, never()).create(any(), any(), any());
  }

  @Test
  void givenTokenIssuerIsConfigured_whenAuthenticate_thenDecoderIsBuiltWithConfiguredIssuerAndReusedAcrossCalls() {
    final var opProperties = new OpenidProviderProperties();
    opProperties.setIss(URI.create("https://op/realm"));
    opProperties.setAud("bff");
    when(opPropertiesResolver.resolve(any())).thenReturn(Optional.of(opProperties));
    when(jwtDecoderFactory.create(any(), any(), any())).thenReturn(jwtDecoder);
    when(jwtDecoder.decode(any())).thenThrow(new InvalidBearerTokenException("not signed"));
    final var manager = new JWTClaimsSetAuthenticationManager(opPropertiesResolver,
        jwtDecoderFactory, jwtAuthenticationConverter);

    assertThatThrownBy(() -> manager.authenticate(bearer("https://op/realm", "ch4mp")))
        .isInstanceOf(InvalidBearerTokenException.class);
    assertThatThrownBy(() -> manager.authenticate(bearer("https://op/realm", "tonton")))
        .isInstanceOf(InvalidBearerTokenException.class);

    verify(jwtDecoderFactory).create(eq(Optional.empty()),
        eq(Optional.of(URI.create("https://op/realm"))), eq(Optional.of("bff")));
  }

  @Test
  void givenOpenidProviderHasJwkSetUriButNoIssuer_whenAuthenticate_thenTokenIssuerIsUsedForValidationOnly() {
    final var opProperties = new OpenidProviderProperties();
    opProperties.setJwkSetUri(URI.create("https://op/jwks"));
    when(opPropertiesResolver.resolve(any())).thenReturn(Optional.of(opProperties));
    when(jwtDecoderFactory.create(any(), any(), any())).thenReturn(jwtDecoder);
    when(jwtDecoder.decode(any())).thenThrow(new InvalidBearerTokenException("not signed"));
    final var manager = new JWTClaimsSetAuthenticationManager(opPropertiesResolver,
        jwtDecoderFactory, jwtAuthenticationConverter);

    assertThatThrownBy(() -> manager.authenticate(bearer("https://op/realm", "ch4mp")))
        .isInstanceOf(InvalidBearerTokenException.class);

    verify(jwtDecoderFactory).create(eq(Optional.of(URI.create("https://op/jwks"))),
        eq(Optional.of(URI.create("https://op/realm"))), eq(Optional.empty()));
  }

  @Test
  void givenOpenidProviderHasNeitherJwkSetUriNorIssuer_whenAuthenticate_thenTokenIssuerIsNotUsedForDiscovery() {
    final var opProperties = new OpenidProviderProperties();
    when(opPropertiesResolver.resolve(any())).thenReturn(Optional.of(opProperties));
    when(jwtDecoderFactory.create(any(), any(), any())).thenReturn(jwtDecoder);
    when(jwtDecoder.decode(any())).thenThrow(new InvalidBearerTokenException("not signed"));
    final var manager = new JWTClaimsSetAuthenticationManager(opPropertiesResolver,
        jwtDecoderFactory, jwtAuthenticationConverter);

    assertThatThrownBy(() -> manager.authenticate(bearer("https://attacker", "ch4mp")))
        .isInstanceOf(InvalidBearerTokenException.class);

    verify(jwtDecoderFactory).create(eq(Optional.empty()), eq(Optional.empty()),
        eq(Optional.empty()));
    assertThat(opProperties.getIss()).isNull();
  }

  private static BearerTokenAuthenticationToken bearer(String issuer, String subject) {
    final var claims = new JWTClaimsSet.Builder().subject(subject);
    if (issuer != null) {
      claims.issuer(issuer);
    }
    return new BearerTokenAuthenticationToken(new PlainJWT(claims.build()).serialize());
  }
}
