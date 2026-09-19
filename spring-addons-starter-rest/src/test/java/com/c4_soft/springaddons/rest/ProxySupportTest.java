package com.c4_soft.springaddons.rest;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties.ProxyProperties;

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

  @Test
  void givenSystemProxyWithoutPort_whenGetPort_thenSchemeDefaultPort() {
    final var noProperties = new ProxyProperties();

    assertThat(new ProxySupport(new SystemProxyProperties(Optional.of("http://proxy.corp"),
        List.of()), noProperties).getPort()).isEqualTo(80);
    assertThat(new ProxySupport(new SystemProxyProperties(Optional.of("https://proxy.corp"),
        List.of()), noProperties).getPort()).isEqualTo(443);
    assertThat(new ProxySupport(new SystemProxyProperties(Optional.of("http://proxy.corp:3128"),
        List.of()), noProperties).getPort()).isEqualTo(3128);
  }

  @Test
  void givenSystemProxyWithUserInfo_whenGetUsernameAndPassword_thenParsed() {
    final var support = new ProxySupport(
        new SystemProxyProperties(Optional.of("http://user:s3cret@proxy.corp:3128"), List.of()),
        new ProxyProperties());

    assertThat(support.isEnabled()).isTrue();
    assertThat(support.getHostname()).contains("proxy.corp");
    assertThat(support.getProtocol()).isEqualTo("http");
    assertThat(support.getUsername()).isEqualTo("user");
    assertThat(support.getPassword()).isEqualTo("s3cret");
  }

  @Test
  void givenProxyPropertiesHost_whenGet_thenPropertiesWinOverSystemProxy() {
    final var properties = new ProxyProperties();
    properties.setHost(Optional.of("corp-proxy"));
    properties.setPort(8080);
    properties.setProtocol("https");
    final var support = new ProxySupport(
        new SystemProxyProperties(Optional.of("http://user:s3cret@proxy.corp:3128"), List.of()),
        properties);

    assertThat(support.getHostname()).contains("corp-proxy");
    assertThat(support.getPort()).isEqualTo(8080);
    assertThat(support.getProtocol()).isEqualTo("https");
    assertThat(support.getUsername()).isNull();
  }

  private static Pattern pattern(String... entries) {
    return Pattern.compile(ProxySupport.getNonProxyHostsPattern(List.of(entries)));
  }
}
