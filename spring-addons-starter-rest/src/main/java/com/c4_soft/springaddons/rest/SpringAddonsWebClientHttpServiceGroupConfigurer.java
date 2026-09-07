package com.c4_soft.springaddons.rest;

import java.util.Optional;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.boot.http.client.reactive.ClientHttpConnectorBuilder;
import org.springframework.context.ApplicationContext;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.support.WebClientHttpServiceGroupConfigurer;
import org.springframework.web.service.registry.HttpServiceGroupConfigurer;

/**
 * <p>
 * Backs {@code @ImportHttpServices} groups referenced from
 * "com.c4-soft.springaddons.rest.group" with the same configuration (connector, base URL,
 * headers, authorization) as the already auto-configured {@link WebClient} bean of the referenced
 * client-id.
 * </p>
 * <p>
 * Configuration is re-applied to the group's own {@link WebClient.Builder} through a
 * {@link HttpServiceGroupConfigurer.ClientCallback} rather than obtained via
 * {@link WebClient#mutate()} through a
 * {@link HttpServiceGroupConfigurer.InitializingClientCallback}: Spring Boot's own
 * {@code PropertiesWebClientHttpServiceGroupConfigurer} unconditionally touches every WEB_CLIENT
 * group at the highest possible precedence ({@code Ordered.HIGHEST_PRECEDENCE}, which this
 * library cannot outrank), which would make an {@code InitializingClientCallback} registered here
 * fail with "Client builder already initialized". {@code ClientCallback} has no such exclusivity
 * constraint, at the cost of the group getting its own
 * {@link org.springframework.http.client.reactive.ClientHttpConnector} instance (same
 * configuration, independent connection pool) rather than literally sharing the client-id bean's
 * one.
 * </p>
 * <p>
 * Subclassed once per stack (reactive / servlet exposing {@code WebClient}) because building the
 * OAuth2 authorization exchange filter function requires different collaborators
 * ({@code ReactiveOAuth2AuthorizedClientManager} vs {@code OAuth2AuthorizedClientManager} +
 * {@code ClientRegistrationRepository}).
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public abstract class SpringAddonsWebClientHttpServiceGroupConfigurer
    implements WebClientHttpServiceGroupConfigurer {

  protected final SpringAddonsRestProperties restProperties;
  protected final ApplicationContext applicationContext;

  protected SpringAddonsWebClientHttpServiceGroupConfigurer(SpringAddonsRestProperties restProperties,
      ApplicationContext applicationContext) {
    this.restProperties = restProperties;
    this.applicationContext = applicationContext;
  }

  @Override
  public void configureGroups(Groups<WebClient.Builder> groups) {
    final var groupNames = restProperties.getGroup().keySet();
    if (groupNames.isEmpty()) {
      return;
    }
    groups.filterByName(groupNames.toArray(new String[groupNames.size()])).forEachClient(
        (HttpServiceGroupConfigurer.ClientCallback<WebClient.Builder>) (group,
            clientBuilder) -> configureClient(group.name(), clientBuilder));
  }

  private void configureClient(String groupName, WebClient.Builder clientBuilder) {
    final var clientId = restProperties.getGroup().get(groupName).getClient();
    if (!restProperties.getClient().containsKey(clientId)) {
      throw new RestConfigurationNotFoundException(clientId);
    }

    final var factoryBean = newFactoryBean();
    factoryBean.setClientId(clientId);
    factoryBean.setRestProperties(restProperties);
    factoryBean.setApplicationContext(applicationContext);
    factoryBean.setSystemProxyProperties(applicationContext.getBeanProvider(SystemProxyProperties.class)
        .getIfAvailable(SystemProxyProperties::new));
    factoryBean.setClientHttpConnectorBuilder(resolveConnectorBuilder());
    // Fold "spring.http.serviceclient.<groupName>.*" in as the base settings, so it is not
    // silently discarded by the spring-addons client-id configuration re-applied below (which
    // takes precedence when it explicitly sets a value).
    final var contextHttpClientSettings = resolve(HttpClientSettings.class);
    factoryBean.setHttpClientSettings(HttpServiceGroupSettingsResolver
        .resolveGroupOverride(groupName, applicationContext, contextHttpClientSettings)
        .or(() -> contextHttpClientSettings));

    factoryBean.configure(clientBuilder);
  }

  /**
   * Creates a stack-specific {@link AbstractWebClientBuilderFactoryBean}, with its OAuth2
   * collaborators already set (client-id, restProperties, applicationContext, proxy, connector
   * builder and HTTP client settings are set by this class).
   */
  protected abstract AbstractWebClientBuilderFactoryBean newFactoryBean();

  protected final <T> Optional<T> resolve(Class<T> type) {
    return Optional.ofNullable(applicationContext.getBeanProvider(type).getIfAvailable());
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private Optional<ClientHttpConnectorBuilder<?>> resolveConnectorBuilder() {
    final ClientHttpConnectorBuilder builder =
        applicationContext.getBeanProvider(ClientHttpConnectorBuilder.class).getIfAvailable();
    return Optional.ofNullable(builder);
  }
}
