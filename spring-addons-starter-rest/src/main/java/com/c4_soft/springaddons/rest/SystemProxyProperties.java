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
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * <p>
 * Configuration for HTTP or SOCKS proxy.
 * </p>
 * <p>
 * HTTP_PROXY and NO_PROXY standard environment variable are used only if
 * com.c4-soft.springaddons.rest.proxy.hostname is left empty and
 * com.c4-soft.springaddons.rest.proxy.enabled is TRUE or null.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Data
@AutoConfiguration
@ConfigurationProperties
@AllArgsConstructor
@NoArgsConstructor
public class SystemProxyProperties {

  /* also parse standard environment variables */
  @Value("${http_proxy:#{null}}")
  private Optional<String> httpProxy = Optional.empty();

  @Value("${no_proxy:}")
  private List<String> noProxy = List.of();

  public Optional<URL> getHttpProxy() {
    return httpProxy.filter(StringUtils::hasText).map(t -> {
      try {
        return URI.create(t.trim()).toURL();
      } catch (MalformedURLException | IllegalArgumentException e) {
        throw new RestMisconfigurationException(
            "http_proxy '%s' is not a valid URL: %s".formatted(t, e.getMessage()));
      }
    });
  }
}
