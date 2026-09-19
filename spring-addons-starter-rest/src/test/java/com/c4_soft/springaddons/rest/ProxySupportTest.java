package com.c4_soft.springaddons.rest;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class ProxySupportTest {

  @Test
  void givenNoEntries_whenGetNonProxyHostsPattern_thenNull() {
    assertThat(ProxySupport.getNonProxyHostsPattern(null)).isNull();
    assertThat(ProxySupport.getNonProxyHostsPattern(List.of())).isNull();
    assertThat(ProxySupport.getNonProxyHostsPattern(List.of(" ", ""))).isNull();
  }

  @Test
  void givenLiteralEntries_whenGetNonProxyHostsPattern_thenExactHostsOnly() {
    final var pattern = pattern("localhost", "bravo-ch4mp", "10.0.0.1");

    assertThat(pattern.matcher("localhost").matches()).isTrue();
    assertThat(pattern.matcher("bravo-ch4mp").matches()).isTrue();
    assertThat(pattern.matcher("10.0.0.1").matches()).isTrue();
    // dots are not wildcards
    assertThat(pattern.matcher("10a0b0c1").matches()).isFalse();
    assertThat(pattern.matcher("localhost.evil").matches()).isFalse();
  }

  @Test
  void givenLeadingDotEntry_whenGetNonProxyHostsPattern_thenDomainAndSubDomainsMatch() {
    final var pattern = pattern(".corporate-domain.pf");

    assertThat(pattern.matcher("corporate-domain.pf").matches()).isTrue();
    assertThat(pattern.matcher("server.corporate-domain.pf").matches()).isTrue();
    assertThat(pattern.matcher("a.b.corporate-domain.pf").matches()).isTrue();
    assertThat(pattern.matcher("evil-corporate-domain.pf").matches()).isFalse();
  }

  @Test
  void givenWildcardEntries_whenGetNonProxyHostsPattern_thenPatternIsValidAndMatches() {
    final var pattern = pattern("*.example.com", "api-*.internal");

    assertThat(pattern.matcher("www.example.com").matches()).isTrue();
    assertThat(pattern.matcher("example.com").matches()).isFalse();
    assertThat(pattern.matcher("api-42.internal").matches()).isTrue();
    assertThat(pattern.matcher("api.internal").matches()).isFalse();
  }

  @Test
  void givenStarAlone_whenGetNonProxyHostsPattern_thenEverythingMatches() {
    final var pattern = pattern("*");

    assertThat(pattern.matcher("anything.example.com").matches()).isTrue();
  }

  private static Pattern pattern(String... entries) {
    return Pattern.compile(ProxySupport.getNonProxyHostsPattern(List.of(entries)));
  }
}
