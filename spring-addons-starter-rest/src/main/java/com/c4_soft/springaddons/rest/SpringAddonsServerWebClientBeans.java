package com.c4_soft.springaddons.rest;

import java.util.List;
import java.util.Optional;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientType;
import lombok.Setter;

/**
 * Applied only in reactive (WebFlux) applications.
 * 
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@ConditionalOnWebApplication(type = Type.REACTIVE)
@AutoConfiguration
public class SpringAddonsServerWebClientBeans {

  @Bean
  SpringAddonsServerWebClientBeanDefinitionRegistryPostProcessor springAddonsWebClientBeanDefinitionRegistryPostProcessor(
      Environment environment) {
    return new SpringAddonsServerWebClientBeanDefinitionRegistryPostProcessor(environment);
  }

  /**
   * <p>
   * Post process the {@link BeanDefinitionRegistry} to add a {@link WebClient} (or
   * {@link WebClient.builder}) bean definitions for each entry in
   * "com.c4-soft.springaddons.rest.client".
   * </p>
   * 
   * <p>
   * Bean definitions include a base URI, header and {@link ReactorClientHttpConnector} for HTTP or
   * SOCKS proxy, as well as exchange function for Basic or OAuth2 (Bearer) authorization.
   * </p>
   * 
   * <p>
   * The bean names are by default the camelCase transformation of the client-id, suffixed with
   * "Builder" if the expose-builder property is true.
   * </p>
   * 
   * @author ch4mp&#64;c4-soft.com
   */
  static class SpringAddonsServerWebClientBeanDefinitionRegistryPostProcessor
      implements BeanDefinitionRegistryPostProcessor {

    private final SpringAddonsRestProperties restProperties;
    private final SystemProxyProperties systemProxyProperties;

    @SuppressWarnings("unchecked")
    public SpringAddonsServerWebClientBeanDefinitionRegistryPostProcessor(Environment environment) {
      this.restProperties = Binder.get(environment)
          .bind("com.c4-soft.springaddons.rest", SpringAddonsRestProperties.class)
          .orElseThrow(() -> new RestMisconfigurationException(
              "Could not read spring-addons REST properties"));

      final var httpProxy = Optional
          .ofNullable(Binder.get(environment).bind("http-proxy", String.class).orElse(null));
      final var noProxy = Binder.get(environment).bind("no-proxy", List.class).orElse(List.of());
      this.systemProxyProperties = new SystemProxyProperties(httpProxy, noProxy);
    }

    @Override
    public void postProcessBeanDefinitionRegistry(@NonNull BeanDefinitionRegistry registry)
        throws BeansException {

      restProperties.getClient().entrySet().stream()
          .filter(e -> ClientType.WEB_CLIENT.equals(e.getValue().getType())
              || ClientType.DEFAULT.equals(e.getValue().getType()))
          .forEach(e -> {
            final var builder = e.getValue().isExposeBuilder()
                ? BeanDefinitionBuilder
                    .genericBeanDefinition(ServerWebClientBuilderFactoryBean.class)
                : BeanDefinitionBuilder.genericBeanDefinition(ServerWebClientFactoryBean.class);
            builder.addPropertyValue("systemProxyProperties", systemProxyProperties);
            builder.addPropertyValue("restProperties", restProperties);
            builder.addAutowiredProperty("clientRegistrationRepository");
            builder.addAutowiredProperty("authorizedClientRepository");
            builder.addPropertyValue("clientId", e.getKey());
            registry.registerBeanDefinition(restProperties.getClientBeanName(e.getKey()),
                builder.getBeanDefinition());
          });

      /*
       * FIXME: for some reason, registering HttpExchangeProxyFactoryBean<T> definitions doesn't
       * work: the clientRegistrationRepo is initialized before OAuth2 client properties are
       * resolved and the HttpExchangeProxyFactoryBean<T> named beans are not resolved when
       * injecting T in components
       */

    }
  }

  @Setter
  public static class ServerWebClientBuilderFactoryBean
      extends AbstractWebClientBuilderFactoryBean {
    private Optional<ReactiveClientRegistrationRepository> clientRegistrationRepository;
    private Optional<ServerOAuth2AuthorizedClientRepository> authorizedClientRepository;

    @Override
    protected ExchangeFilterFunction registrationExchangeFilterFunction(
        String Oauth2RegistrationId) {
      return SpringAddonsServerWebClientSupport.registrationExchangeFilterFunction(
          clientRegistrationRepository.get(), authorizedClientRepository.get(),
          Oauth2RegistrationId);
    }

    @Override
    protected ExchangeFilterFunction forwardingBearerExchangeFilterFunction() {
      return SpringAddonsServerWebClientSupport.forwardingBearerExchangeFilterFunction();
    }
  }

  @Setter
  public static class ServerWebClientFactoryBean implements FactoryBean<WebClient> {
    private String clientId;
    private SystemProxyProperties systemProxyProperties;
    private SpringAddonsRestProperties restProperties;
    private Optional<ReactiveClientRegistrationRepository> clientRegistrationRepository =
        Optional.empty();
    private Optional<ServerOAuth2AuthorizedClientRepository> authorizedClientRepository =
        Optional.empty();

    @Override
    @Nullable
    public WebClient getObject() throws Exception {
      final var builderFactoryBean = new ServerWebClientBuilderFactoryBean();
      builderFactoryBean.setClientId(clientId);
      builderFactoryBean.setSystemProxyProperties(systemProxyProperties);
      builderFactoryBean.setRestProperties(restProperties);
      builderFactoryBean.setClientRegistrationRepository(clientRegistrationRepository);
      builderFactoryBean.setAuthorizedClientRepository(authorizedClientRepository);
      return Optional.ofNullable(builderFactoryBean.getObject()).map(WebClient.Builder::build)
          .orElse(null);
    }

    @Override
    @Nullable
    public Class<?> getObjectType() {
      return WebClient.class;
    }
  }
}
