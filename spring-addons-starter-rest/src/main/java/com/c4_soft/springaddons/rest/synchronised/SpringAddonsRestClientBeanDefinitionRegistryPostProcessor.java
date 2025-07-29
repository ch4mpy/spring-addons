package com.c4_soft.springaddons.rest.synchronised;

import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.Environment;
import org.springframework.web.client.RestClient;
import com.c4_soft.springaddons.rest.RestMisconfigurationException;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientType;
import com.c4_soft.springaddons.rest.SystemProxyProperties;

/**
 * <p>
 * Post process the {@link BeanDefinitionRegistry} to add a {@link RestClient} (or
 * {@link RestClient.Builder}) bean definitions for each entry in
 * "com.c4-soft.springaddons.rest.client".
 * </p>
 * 
 * <p>
 * The bean names are by default the camelCase transformation of the client-id, suffixed with
 * "Builder" if the expose-builder property is true.
 * </p>
 * 
 * @author ch4mp&#64;c4-soft.com
 */
public class SpringAddonsRestClientBeanDefinitionRegistryPostProcessor
    implements BeanDefinitionRegistryPostProcessor {

  private final SpringAddonsRestProperties restProperties;
  private final SystemProxyProperties systemProxyProperties;

  @SuppressWarnings("unchecked")
  public SpringAddonsRestClientBeanDefinitionRegistryPostProcessor(Environment environment) {
    this.restProperties = Binder.get(environment)
        .bind("com.c4-soft.springaddons.rest", SpringAddonsRestProperties.class)
        .orElseThrow(() -> new RestMisconfigurationException(
            "Could not read spring-addons REST properties"));

    final var httpProxy =
        Optional.ofNullable(Binder.get(environment).bind("http-proxy", String.class).orElse(null));
    final var noProxy = Binder.get(environment).bind("no-proxy", List.class).orElse(List.of());
    this.systemProxyProperties = new SystemProxyProperties(httpProxy, noProxy);
  }

  @Override
  public void postProcessBeanDefinitionRegistry(@NonNull BeanDefinitionRegistry registry)
      throws BeansException {

    restProperties.getClient().entrySet().stream()
        .filter(e -> ClientType.REST_CLIENT.equals(e.getValue().getType())
            || ClientType.DEFAULT.equals(e.getValue().getType()))
        .forEach(e -> {
          final var builder = e.getValue().isExposeBuilder()
              ? BeanDefinitionBuilder.genericBeanDefinition(RestClientBuilderFactoryBean.class)
              : BeanDefinitionBuilder.genericBeanDefinition(RestClientFactoryBean.class);
          final var oAuth2Authorization = e.getValue().getAuthorization().getOauth2();
          builder.addPropertyValue(RestClientFactoryBean.Fields.systemProxyProperties,
              systemProxyProperties);
          builder.addPropertyValue(RestClientFactoryBean.Fields.restProperties, restProperties);
          if (oAuth2Authorization != null
              && oAuth2Authorization.getOauth2RegistrationId().isPresent()) {
            builder.addAutowiredProperty(RestClientFactoryBean.Fields.authorizedClientManager);
            builder.addAutowiredProperty(RestClientFactoryBean.Fields.clientRegistrationRepository);
            builder.addAutowiredProperty(RestClientFactoryBean.Fields.authorizedClientRepository);
          }
          builder.addAutowiredProperty(RestClientFactoryBean.Fields.clientHttpRequestFactory);
          builder.addAutowiredProperty(RestClientFactoryBean.Fields.restClientBuilder);
          builder.addPropertyValue(RestClientFactoryBean.Fields.clientId, e.getKey());
          builder.addAutowiredProperty(RestClientFactoryBean.Fields.ssl);
          registry.registerBeanDefinition(restProperties.getClientBeanName(e.getKey()),
              builder.getBeanDefinition());
        });

    /*
     * FIXME: for some reason, this doesn't work: the clientRegistrationRepo is initialized before
     * OAuth2 client properties are resolved and the HttpExchangeProxyFactoryBean<T> named beans are
     * not resolved when injecting T in components
     */
    // restProperties.getService().entrySet().stream().forEach(e -> {
    // final var builder =
    // BeanDefinitionBuilder.genericBeanDefinition(HttpExchangeProxyFactoryBean.class);
    // try {
    // builder.addConstructorArgValue(Class.forName(e.getValue().getHttpExchangeClass()));
    // } catch (ClassNotFoundException e1) {
    // throw new RestMisconfigurationConfigurationException(
    // "Unknown class %s for REST service to auto-configure"
    // .formatted(e.getValue().getHttpExchangeClass()));
    // }
    // builder.addConstructorArgReference(e.getValue().getClientBeanName());
    // final var beanName = e.getValue().getBeanName().orElse(toCamelCase(e.getKey()));
    // registry.registerBeanDefinition(beanName, builder.getBeanDefinition());
    // });

  }
}
