package com.c4_soft.springaddons.rest;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * <p>
 * Proxy configuration from the standard {@code http_proxy}, {@code https_proxy} and
 * {@code no_proxy} environment variables (upper or lower case).
 * </p>
 * <p>
 * They are used only if {@code com.c4-soft.springaddons.rest.client.<id>.http.proxy.host} is left
 * empty and {@code ...http.proxy.enabled} is true (the default). {@code https_proxy} is used for
 * {@code https://} targets and {@code http_proxy} for {@code http://} ones, each falling back to
 * the other when not set. A client which can't select a proxy per request (WebClient, Reactor)
 * uses {@code https_proxy} first.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Data
@AutoConfiguration
@ConfigurationProperties
@NoArgsConstructor
public class SystemProxyProperties {

  /** Proxy URL for {@code http://} targets, from the {@code http_proxy} environment variable. */
  @Value("${http_proxy:#{null}}")
  private Optional<String> httpProxy = Optional.empty();

  /** Proxy URL for {@code https://} targets, from the {@code https_proxy} environment variable. */
  @Value("${https_proxy:#{null}}")
  private Optional<String> httpsProxy = Optional.empty();

  /**
   * Hosts reached without a proxy, read from the {@code no_proxy} environment variable: a
   * comma-separated list of hostnames or domain suffixes (a leading dot matches subdomains,
   * {@code *} is a wildcard).
   */
  @Value("${no_proxy:}")
  private List<String> noProxy = List.of();

  public SystemProxyProperties(Optional<String> httpProxy, List<String> noProxy) {
    this(httpProxy, Optional.empty(), noProxy);
  }

  public SystemProxyProperties(Optional<String> httpProxy, Optional<String> httpsProxy,
      List<String> noProxy) {
    this.httpProxy = httpProxy;
    this.httpsProxy = httpsProxy;
    this.noProxy = noProxy;
  }

  public Optional<URL> getHttpProxy() {
    return toUrl("http_proxy", httpProxy);
  }

  public Optional<URL> getHttpsProxy() {
    return toUrl("https_proxy", httpsProxy);
  }

  /**
   * @param targetScheme the scheme of the URI a request is sent to ({@code http} or {@code https}),
   *        or null when unknown
   * @return the proxy for that scheme: {@code https_proxy} for https targets and {@code http_proxy}
   *         for http ones, each falling back to the other. {@code https_proxy} first when the scheme
   *         is unknown.
   */
  public Optional<URL> getProxyFor(String targetScheme) {
    if ("http".equalsIgnoreCase(targetScheme)) {
      return getHttpProxy().or(this::getHttpsProxy);
    }
    return getHttpsProxy().or(this::getHttpProxy);
  }

  private static Optional<URL> toUrl(String name, Optional<String> value) {
    return Optional.ofNullable(value).flatMap(v -> v).filter(StringUtils::hasText).map(t -> {
      try {
        return URI.create(t.trim()).toURL();
      } catch (MalformedURLException | IllegalArgumentException e) {
        throw new RestMisconfigurationException(
            "%s '%s' is not a valid URL: %s".formatted(name, t, e.getMessage()));
      }
    });
  }
}
