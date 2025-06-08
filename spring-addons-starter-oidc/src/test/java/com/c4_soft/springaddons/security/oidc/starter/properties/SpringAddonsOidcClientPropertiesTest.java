package com.c4_soft.springaddons.security.oidc.starter.properties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class SpringAddonsOidcClientPropertiesTest {
  SpringAddonsOidcClientProperties properties;

  @Test
  void givenDefaultProperties_whenGetPostLoginUriOrGetPostLogoutUri_thenAuthorityIsTheSameAsClientUriProperty() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setPostLoginRedirectPath(Optional.of("/ui/account"));
    properties.setPostLogoutRedirectPath(Optional.of("/ui/"));

    properties.setClientUri(Optional.of(URI.create("https://localhost/bff")));
    assertEquals(URI.create("https://localhost/ui/account"), properties.getPostLoginRedirectUri());
    assertEquals(URI.create("https://localhost/ui/"), properties.getPostLogoutRedirectUri());

    properties.setClientUri(Optional.of(URI.create("/bff")));
    assertEquals(URI.create("/ui/account"), properties.getPostLoginRedirectUri());
    assertEquals(URI.create("/ui/"), properties.getPostLogoutRedirectUri());
  }

  @Test
  void givenPostLoginHostIsSetInProperties_whenGetPostLoginUri_thenSchemeAndAuthorityArethoseOfPostLoginHostProperty() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setPostLoginRedirectHost(Optional.of(URI.create("http://localhost:4200")));
    properties.setPostLoginRedirectPath(Optional.of("/ui/account"));

    properties.setClientUri(Optional.of(URI.create("https://localhost/bff")));
    assertEquals(URI.create("http://localhost:4200/ui/account"),
        properties.getPostLoginRedirectUri());

    properties.setClientUri(Optional.of(URI.create("/bff")));
    assertEquals(URI.create("http://localhost:4200/ui/account"),
        properties.getPostLoginRedirectUri());
  }

  @Test
  void givenPostLogoutHostIsSetInProperties_whenGetPostLogoutUri_thenSchemeAndAuthorityArethoseOfPostLogoutHostProperty() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setPostLogoutRedirectHost(Optional.of(URI.create("http://localhost:4200")));
    properties.setPostLogoutRedirectPath(Optional.of("/ui/"));

    properties.setClientUri(Optional.of(URI.create("https://localhost/bff")));
    assertEquals(URI.create("http://localhost:4200/ui/"), properties.getPostLogoutRedirectUri());

    properties.setClientUri(Optional.of(URI.create("/bff")));
    assertEquals(URI.create("http://localhost:4200/ui/"), properties.getPostLogoutRedirectUri());
  }

  @Test
  void givenClientUriHasSchemeAndAuthority_whenGetDefaultPostLoginAllowedUriPatterns_thenTwoPatterns() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("http://localhost:8080/bff")));

    final var actual =
        properties.getPostLoginAllowedUriPatterns().stream().map(Pattern::toString).toList();

    assertEquals(2, actual.size());
    assertThat(actual).containsExactlyInAnyOrder("^http://localhost:8080(/.*)?$", "^/.*$");
  }

  @Test
  void givenClientUriHasNoSchemeAndAuthority_whenGetDefaultPostLoginAllowedUriPatterns_thenOnePattern() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("/bff")));

    final var actual =
        properties.getPostLoginAllowedUriPatterns().stream().map(Pattern::toString).toList();

    assertEquals(1, actual.size());
    assertEquals(actual.get(0), "^/.*$");
  }

  @Test
  void givenClientUriHasSchemeAndAuthority_whenGetDefaultPostLogoutAllowedUriPatterns_thenTwoPatterns() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("http://localhost:8080/bff")));

    final var actual =
        properties.getPostLogoutAllowedUriPatterns().stream().map(Pattern::toString).toList();

    assertEquals(2, actual.size());
    assertThat(actual).containsExactlyInAnyOrder("^http://localhost:8080(/.*)?$", "^/.*$");
  }

  @Test
  void givenClientUriHasNoSchemeAndAuthority_whenGetDefaultPostLogoutAllowedUriPatterns_thenOnePattern() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("/bff")));

    final var actual =
        properties.getPostLogoutAllowedUriPatterns().stream().map(Pattern::toString).toList();

    assertEquals(1, actual.size());
    assertEquals(actual.get(0), "^/.*$");
  }

  @Test
  void givenPostLoginUriPatternsAreSpecified_whenGetPostLoginAllowedUriPatterns_thenUsed() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("https://localhost/bff")));
    properties.setPostLoginAllowedUriPatterns(
        List.of(Pattern.compile("https://localhost/ui(/.*)?"), Pattern.compile("/ui(/.*)?")));

    final var actual =
        properties.getPostLoginAllowedUriPatterns().stream().map(Pattern::toString).toList();

    assertEquals(2, actual.size());
    assertThat(actual).containsExactlyInAnyOrder("https://localhost/ui(/.*)?", "/ui(/.*)?");
  }

  @Test
  void givenPostLogoutUriPatternsAreSpecified_whenGetPostLogoutAllowedUriPatterns_thenUsed() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("https://localhost/bff")));
    properties.setPostLogoutAllowedUriPatterns(
        List.of(Pattern.compile("https://localhost/ui(/)?"), Pattern.compile("/ui(/)?")));

    final var actual =
        properties.getPostLogoutAllowedUriPatterns().stream().map(Pattern::toString).toList();

    assertEquals(2, actual.size());
    assertThat(actual).containsExactlyInAnyOrder("https://localhost/ui(/)?", "/ui(/)?");
  }

}
