package com.c4_soft.springaddons.rest.synchronised;

import java.util.Optional;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.context.ApplicationContext;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.support.RestClientHttpServiceGroupConfigurer;
import org.springframework.web.service.registry.HttpServiceGroupConfigurer;
import com.c4_soft.springaddons.rest.RestConfigurationNotFoundException;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties;
import com.c4_soft.springaddons.rest.SystemProxyProperties;

/**
 * <p>
 * Backs {@code @ImportHttpServices} groups referenced from
 * "com.c4-soft.springaddons.rest.group" with the same configuration (request factory, base URL,
 * headers, authorization) as the already auto-configured {@link RestClient} bean of the
 * referenced client-id.
 * </p>
 * <p>
 * Configuration is re-applied to the group's own {@link RestClient.Builder} through a
 * {@link HttpServiceGroupConfigurer.ClientCallback} rather than obtained via
 * {@link RestClient#mutate()} through a
 * {@link HttpServiceGroupConfigurer.InitializingClientCallback}: Spring Boot's own
 * {@code PropertiesRestClientHttpServiceGroupConfigurer} unconditionally touches every REST_CLIENT
 * group at (near) the highest precedence, which would make an {@code InitializingClientCallback}
 * registered by this library fail with "Client builder already initialized" for any group it runs
 * after. {@code ClientCallback} has no such exclusivity constraint, at the cost of the group
 * getting its own {@link ClientHttpRequestFactory} instance (same configuration, independent
 * connection pool) rather than literally sharing the client-id bean's one.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class SpringAddonsRestClientHttpServiceGroupConfigurer
    implements RestClientHttpServiceGroupConfigurer {

  private final SpringAddonsRestProperties restProperties;
  private final ApplicationContext applicationContext;

  public SpringAddonsRestClientHttpServiceGroupConfigurer(SpringAddonsRestProperties restProperties,
      ApplicationContext applicationContext) {
    this.restProperties = restProperties;
    this.applicationContext = applicationContext;
  }

  @Override
  public void configureGroups(Groups<RestClient.Builder> groups) {
    final var groupNames = restProperties.getGroup().keySet();
    if (groupNames.isEmpty()) {
      return;
    }
    groups.filterByName(groupNames.toArray(new String[groupNames.size()])).forEachClient(
        (HttpServiceGroupConfigurer.ClientCallback<RestClient.Builder>) (group,
            clientBuilder) -> configureClient(group.name(), clientBuilder));
  }

  private void configureClient(String groupName, RestClient.Builder clientBuilder) {
    final var clientId = restProperties.getGroup().get(groupName).getClient();
    if (!restProperties.getClient().containsKey(clientId)) {
      throw new RestConfigurationNotFoundException(clientId);
    }

    final var factoryBean = new RestClientBuilderFactoryBean();
    factoryBean.setClientId(clientId);
    factoryBean.setRestProperties(restProperties);
    factoryBean.setApplicationContext(applicationContext);
    factoryBean.setSystemProxyProperties(applicationContext.getBeanProvider(SystemProxyProperties.class)
        .getIfAvailable(SystemProxyProperties::new));
    factoryBean.setAuthorizedClientManager(resolve(OAuth2AuthorizedClientManager.class));
    factoryBean.setClientRegistrationRepository(resolve(ClientRegistrationRepository.class));
    factoryBean.setAuthorizedClientRepository(resolve(OAuth2AuthorizedClientRepository.class));
    factoryBean.setClientHttpRequestFactory(resolve(ClientHttpRequestFactory.class));
    factoryBean.setClientHttpRequestFactoryBuilder(resolveRequestFactoryBuilder());
    factoryBean.setHttpClientSettings(resolve(HttpClientSettings.class));

    factoryBean.configure(clientBuilder);
  }

  private <T> Optional<T> resolve(Class<T> type) {
    return Optional.ofNullable(applicationContext.getBeanProvider(type).getIfAvailable());
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private Optional<ClientHttpRequestFactoryBuilder<?>> resolveRequestFactoryBuilder() {
    final ClientHttpRequestFactoryBuilder builder =
        applicationContext.getBeanProvider(ClientHttpRequestFactoryBuilder.class).getIfAvailable();
    return Optional.ofNullable(builder);
  }
}
