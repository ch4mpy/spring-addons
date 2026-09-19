package com.c4_soft.springaddons.rest;

import java.net.URL;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties.ProxyProperties;
import org.jspecify.annotations.Nullable;

/**
 * Used when configuring a {@link RestClient} or {@link WebClient} instance to authenticate on an
 * HTTP or SOCKS proxy.
 * 
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class ProxySupport {
  private final SystemProxyProperties systemProxyProperties;
  private final ProxyProperties springAddonsProperties;
  private final @Nullable String targetScheme;

  /**
   * A proxy support for a client which can't select a proxy per request: {@code https_proxy} is
   * preferred over {@code http_proxy} (see {@link SystemProxyProperties#getProxyFor(String)})
   */
  public ProxySupport(SystemProxyProperties systemProxyProperties,
      ProxyProperties springAddonsProperties) {
    this(systemProxyProperties, springAddonsProperties, null);
  }

  /**
   * @param targetScheme the scheme of the requests going through this proxy ({@code http} or
   *        {@code https}), which selects between {@code http_proxy} and {@code https_proxy}
   */
  public ProxySupport(SystemProxyProperties systemProxyProperties,
      ProxyProperties springAddonsProperties, @Nullable String targetScheme) {
    this.systemProxyProperties = systemProxyProperties;
    this.springAddonsProperties = springAddonsProperties;
    this.targetScheme = targetScheme;
  }

  private Optional<URL> systemProxy() {
    return systemProxyProperties.getProxyFor(targetScheme);
  }

  public boolean isEnabled() {
    return springAddonsProperties.isEnabled() && getHostname().isPresent();
  }

  public Optional<String> getHostname() {
    if (!springAddonsProperties.isEnabled()) {
      return Optional.empty();
    }
    return springAddonsProperties.getHost()
        .or(() -> systemProxy().map(URL::getHost));
  }

  public String getProtocol() {
    if (!springAddonsProperties.isEnabled()) {
      return null;
    }
    return springAddonsProperties.getHost().map(h -> springAddonsProperties.getProtocol())
        .orElse(systemProxy().map(URL::getProtocol).orElse(null));
  }

  public int getPort() {
    return springAddonsProperties.getHost().map(h -> springAddonsProperties.getPort())
        .orElse(systemProxy().map(ProxySupport::portOf)
            .orElse(springAddonsProperties.getPort()));
  }

  /**
   * @return the explicit port of the proxy URL, or the default port of its scheme
   *         ({@code http_proxy=http://proxy.corp} means port 80)
   */
  private static int portOf(URL proxyUrl) {
    return proxyUrl.getPort() > -1 ? proxyUrl.getPort() : proxyUrl.getDefaultPort();
  }

  /**
   * @return the username from properties when the proxy host is set in properties (credentials of
   *         the system proxy are not sent to another proxy), the system proxy user-info otherwise
   */
  public String getUsername() {
    if (!springAddonsProperties.isEnabled()) {
      return null;
    }
    if (springAddonsProperties.getHost().isPresent()) {
      return springAddonsProperties.getUsername();
    }
    return systemProxy().map(URL::getUserInfo)
        .map(ProxySupport::getUserinfoName).orElse(null);
  }

  /**
   * @return the password from properties when the proxy host is set in properties (credentials of
   *         the system proxy are not sent to another proxy), the system proxy user-info otherwise
   */
  public String getPassword() {
    if (!springAddonsProperties.isEnabled()) {
      return null;
    }
    if (springAddonsProperties.getHost().isPresent()) {
      return springAddonsProperties.getPassword();
    }
    return systemProxy().map(URL::getUserInfo)
        .map(ProxySupport::getUserinfoPassword).orElse(null);
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

  /**
   * <p>
   * Turns {@code no_proxy} entries into a regular expression matching the hosts to reach without
   * going through the proxy.
   * </p>
   * <ul>
   * <li>{@code *} matches anything ({@code *.example.com}, or {@code *} alone to bypass the proxy
   * for every host)</li>
   * <li>an entry starting with a dot matches the domain and all its sub-domains
   * ({@code .example.com} matches {@code example.com} and {@code api.example.com})</li>
   * <li>everything else is matched literally (so {@code .} in host names is not a wildcard)</li>
   * </ul>
   *
   * @param noProxy the {@code no_proxy} entries
   * @return the pattern, or null if there is no entry
   */
  static String getNonProxyHostsPattern(List<String> noProxy) {
    if (noProxy == null) {
      return null;
    }
    final var entries = noProxy.stream().map(String::trim).filter(StringUtils::hasText).toList();
    if (entries.isEmpty()) {
      return null;
    }
    return entries.stream().map(ProxySupport::nonProxyHostPattern)
        .collect(Collectors.joining(")|(", "(", ")"));
  }

  private static String nonProxyHostPattern(String entry) {
    if (entry.startsWith(".")) {
      return "(.*\\.)?" + wildcardsToRegex(entry.substring(1));
    }
    return wildcardsToRegex(entry);
  }

  private static String wildcardsToRegex(String host) {
    return Stream.of(host.split("\\*", -1)).map(Pattern::quote).collect(Collectors.joining(".*"));
  }
}
