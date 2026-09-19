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
    assertThat(actual).containsExactlyInAnyOrder("^\\Qhttp://localhost:8080\\E(/.*)?$",
        "^/(?!/).*$");
  }

  @Test
  void givenClientUriHasNoSchemeAndAuthority_whenGetDefaultPostLoginAllowedUriPatterns_thenOnePattern() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("/bff")));

    final var actual =
        properties.getPostLoginAllowedUriPatterns().stream().map(Pattern::toString).toList();

    assertEquals(1, actual.size());
    assertEquals("^/(?!/).*$", actual.get(0));
  }

  @Test
  void givenClientUriHasSchemeAndAuthority_whenGetDefaultPostLogoutAllowedUriPatterns_thenTwoPatterns() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("http://localhost:8080/bff")));

    final var actual =
        properties.getPostLogoutAllowedUriPatterns().stream().map(Pattern::toString).toList();

    assertEquals(2, actual.size());
    assertThat(actual).containsExactlyInAnyOrder("^\\Qhttp://localhost:8080\\E(/.*)?$",
        "^/(?!/).*$");
  }

  @Test
  void givenClientUriHasNoSchemeAndAuthority_whenGetDefaultPostLogoutAllowedUriPatterns_thenOnePattern() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("/bff")));

    final var actual =
        properties.getPostLogoutAllowedUriPatterns().stream().map(Pattern::toString).toList();

    assertEquals(1, actual.size());
    assertEquals("^/(?!/).*$", actual.get(0));
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

  @Test
  void givenDefaultPatternsForClientUriWithAuthority_whenIsAllowedRedirectionUri_thenPathsAndSameOriginAreAllowed() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("https://app.example.com/bff")));
    final var patterns = properties.getPostLoginAllowedUriPatterns();

    assertThat(SpringAddonsOidcClientProperties.isAllowedRedirectionUri("/", patterns)).isTrue();
    assertThat(SpringAddonsOidcClientProperties.isAllowedRedirectionUri("/ui/account?x=1#f",
        patterns)).isTrue();
    assertThat(SpringAddonsOidcClientProperties.isAllowedRedirectionUri("https://app.example.com",
        patterns)).isTrue();
    assertThat(SpringAddonsOidcClientProperties
        .isAllowedRedirectionUri("https://app.example.com/ui/account", patterns)).isTrue();
  }

  @Test
  void givenDefaultPatterns_whenIsAllowedRedirectionUriWithOtherHost_thenRefused() {
    final var properties = new SpringAddonsOidcClientProperties();
    properties.setClientUri(Optional.of(URI.create("https://app.example.com/bff")));
    final var patterns = properties.getPostLoginAllowedUriPatterns();

    // scheme-relative URIs would pass a "path only" pattern but lead to another host
    assertThat(SpringAddonsOidcClientProperties.isAllowedRedirectionUri("//evil.com/x", patterns))
        .isFalse();
    assertThat(SpringAddonsOidcClientProperties.isAllowedRedirectionUri("///evil.com/x", patterns))
        .isFalse();
    assertThat(SpringAddonsOidcClientProperties.isAllowedRedirectionUri("//evil.com", patterns))
        .isFalse();
    // dots in the client host are not wildcards
    assertThat(SpringAddonsOidcClientProperties
        .isAllowedRedirectionUri("https://appXexampleYcom/", patterns)).isFalse();
    // other hosts, sub-domains and "user info" tricks
    assertThat(SpringAddonsOidcClientProperties.isAllowedRedirectionUri("https://evil.com/",
        patterns)).isFalse();
    assertThat(SpringAddonsOidcClientProperties
        .isAllowedRedirectionUri("https://app.example.com.evil.com/", patterns)).isFalse();
    assertThat(SpringAddonsOidcClientProperties
        .isAllowedRedirectionUri("https://app.example.com@evil.com/", patterns)).isFalse();
    assertThat(SpringAddonsOidcClientProperties.isAllowedRedirectionUri("http://app.example.com/",
        patterns)).isFalse();
    // malformed
    assertThat(SpringAddonsOidcClientProperties.isAllowedRedirectionUri("/\\evil.com", patterns))
        .isFalse();
    assertThat(SpringAddonsOidcClientProperties.isAllowedRedirectionUri("", patterns)).isFalse();
    assertThat(SpringAddonsOidcClientProperties.isAllowedRedirectionUri(null, patterns)).isFalse();
  }

  @Test
  void givenUserProvidedPathOnlyPattern_whenIsAllowedRedirectionUriWithSchemeRelativeUri_thenRefused() {
    final var patterns = List.of(Pattern.compile("/.*"));

    assertThat(SpringAddonsOidcClientProperties.isAllowedRedirectionUri("/ui", patterns)).isTrue();
    assertThat(SpringAddonsOidcClientProperties.isAllowedRedirectionUri("//evil.com/ui", patterns))
        .isFalse();
  }

}
