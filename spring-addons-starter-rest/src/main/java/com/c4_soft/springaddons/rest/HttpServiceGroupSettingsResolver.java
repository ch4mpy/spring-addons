package com.c4_soft.springaddons.rest;

import java.util.Optional;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.boot.http.client.autoconfigure.HttpClientSettingsPropertyMapper;
import org.springframework.boot.http.client.autoconfigure.service.HttpServiceClientProperties;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.ApplicationContext;

/**
 * <p>
 * Resolves a per-group {@link HttpClientSettings} override for an {@code @ImportHttpServices}
 * group backed by "com.c4-soft.springaddons.rest.group", from Spring Boot's own
 * "spring.http.serviceclient.&lt;group-name&gt;.*" properties.
 * </p>
 * <p>
 * Spring Boot's own {@code PropertiesRestClientHttpServiceGroupConfigurer} /
 * {@code PropertiesWebClientHttpServiceGroupConfigurer} build a per-group
 * {@link org.springframework.http.client.ClientHttpRequestFactory} /
 * {@link org.springframework.http.client.reactive.ClientHttpConnector} from
 * "spring.http.serviceclient.&lt;group-name&gt;.*" (merged over the context {@link HttpClientSettings})
 * and set it on the group's builder at (near) the highest precedence. Because spring-addons
 * re-applies its own client-id configuration afterwards (see
 * {@code SpringAddonsRestClientHttpServiceGroupConfigurer} /
 * {@code SpringAddonsWebClientHttpServiceGroupConfigurer}), that per-group factory / connector
 * would otherwise be discarded, silently dropping any "spring.http.serviceclient.&lt;group-name&gt;"
 * connect-timeout, read-timeout, redirects, cookie-handling or ssl-bundle. This resolver returns
 * the settings to fold back in as the base for the group, so the precedence becomes: explicit
 * "com.c4-soft.springaddons.rest.client.&lt;id&gt;.http.*" &gt;
 * "spring.http.serviceclient.&lt;group-name&gt;.*" &gt; "spring.http.clients.*".
 * </p>
 * <p>
 * Returns {@link Optional#empty()} when no "spring.http.serviceclient.&lt;group-name&gt;" entry
 * exists, so that callers can keep reusing a context {@code ClientHttpRequestFactory} bean
 * unmodified in that case, exactly as they would for a client outside any group.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public final class HttpServiceGroupSettingsResolver {

  private HttpServiceGroupSettingsResolver() {}

  public static Optional<HttpClientSettings> resolveGroupOverride(String groupName,
      ApplicationContext applicationContext, Optional<HttpClientSettings> contextSettings) {
    final var serviceClientProperties = Optional
        .ofNullable(applicationContext.getBeanProvider(HttpServiceClientProperties.class).getIfAvailable());
    final var groupProperties = serviceClientProperties.map(properties -> properties.get(groupName));
    if (groupProperties.isEmpty()) {
      return Optional.empty();
    }

    final var sslBundles = applicationContext.getBeanProvider(SslBundles.class).getIfAvailable();
    final var mapper =
        new HttpClientSettingsPropertyMapper(sslBundles, contextSettings.orElseGet(HttpClientSettings::defaults));
    return Optional.of(mapper.map(groupProperties.get()));
  }
}
