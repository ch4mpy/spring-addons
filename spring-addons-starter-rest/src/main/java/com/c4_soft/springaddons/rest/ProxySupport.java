package com.c4_soft.springaddons.rest;

import java.net.URL;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties.ProxyProperties;
import lombok.RequiredArgsConstructor;

/**
 * Used when configuring a {@link RestClient} or {@link WebClient} instance to authenticate on an
 * HTTP or SOCKS proxy.
 * 
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
@RequiredArgsConstructor
public class ProxySupport {
  private final SystemProxyProperties systemProxyProperties;
  private final ProxyProperties springAddonsProperties;

  public boolean isEnabled() {
    return springAddonsProperties.isEnabled() && getHostname().isPresent();
  }

  public Optional<String> getHostname() {
    if (!springAddonsProperties.isEnabled()) {
      return Optional.empty();
    }
    return springAddonsProperties.getHost()
        .or(() -> systemProxyProperties.getHttpProxy().map(URL::getHost));
  }

  public String getProtocol() {
    if (!springAddonsProperties.isEnabled()) {
      return null;
    }
    return springAddonsProperties.getHost().map(h -> springAddonsProperties.getProtocol())
        .orElse(systemProxyProperties.getHttpProxy().map(URL::getProtocol).orElse(null));
  }

  public int getPort() {
    return springAddonsProperties.getHost().map(h -> springAddonsProperties.getPort()).orElse(
        systemProxyProperties.getHttpProxy().map(URL::getPort).orElse(springAddonsProperties.getPort()));
  }

  public String getUsername() {
    if (!springAddonsProperties.isEnabled()) {
      return null;
    }
    return springAddonsProperties.getHost().map(h -> springAddonsProperties.getUsername())
        .orElse(systemProxyProperties.getHttpProxy().map(URL::getUserInfo)
            .map(ProxySupport::getUserinfoName).orElse(null));
  }

  public String getPassword() {
    if (!springAddonsProperties.isEnabled()) {
      return null;
    }
    return springAddonsProperties.getHost().map(h -> springAddonsProperties.getPassword())
        .orElse(systemProxyProperties.getHttpProxy().map(URL::getUserInfo)
            .map(ProxySupport::getUserinfoPassword).orElse(null));
  }

  public String getNoProxy() {
    if (!springAddonsProperties.isEnabled()) {
      return null;
    }
    return Optional.ofNullable(springAddonsProperties.getNonProxyHostsPattern())
        .filter(StringUtils::hasText)
        .orElse(getNonProxyHostsPattern(systemProxyProperties.getNoProxy()));
  }

  public int getConnectTimeoutMillis() {
    return springAddonsProperties.getConnectTimeoutMillis();
  }

  public SystemProxyProperties getSystemProperties() {
    return systemProxyProperties;
  }

  static String getUserinfoName(String userinfo) {
    if (userinfo == null) {
      return null;
    }
    return userinfo.split(":")[0];
  }

  static String getUserinfoPassword(String userinfo) {
    if (userinfo == null) {
      return null;
    }
    final var splits = userinfo.split(":");
    return splits.length < 2 ? null : splits[1];
  }

  static String getNonProxyHostsPattern(List<String> noProxy) {
    if (noProxy == null || noProxy.isEmpty()) {
      return null;
    }
    return noProxy.stream().map(host -> host.replace(".", "\\."))
        .map(host -> host.replace("-", "\\-"))
        .map(host -> host.startsWith("\\.") ? ".*" + host : host)
        .collect(Collectors.joining(")|(", "(", ")"));
  }
}
