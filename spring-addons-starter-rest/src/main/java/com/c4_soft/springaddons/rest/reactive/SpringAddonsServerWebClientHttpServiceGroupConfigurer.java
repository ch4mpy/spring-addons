package com.c4_soft.springaddons.rest.reactive;

import org.springframework.context.ApplicationContext;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import com.c4_soft.springaddons.rest.AbstractWebClientBuilderFactoryBean;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties;
import com.c4_soft.springaddons.rest.SpringAddonsWebClientHttpServiceGroupConfigurer;

/**
 * Reactive (WebFlux) stack variant: backs {@code WebClient} {@code @ImportHttpServices} groups
 * with an auto-configured client, using a {@link ReactiveOAuth2AuthorizedClientManager} to build
 * the OAuth2 authorization filter function when needed.
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class SpringAddonsServerWebClientHttpServiceGroupConfigurer
    extends SpringAddonsWebClientHttpServiceGroupConfigurer {

  public SpringAddonsServerWebClientHttpServiceGroupConfigurer(SpringAddonsRestProperties restProperties,
      ApplicationContext applicationContext) {
    super(restProperties, applicationContext);
  }

  @Override
  protected AbstractWebClientBuilderFactoryBean newFactoryBean() {
    final var factoryBean = new ServerWebClientBuilderFactoryBean();
    factoryBean.setAuthorizedClientManager(resolve(ReactiveOAuth2AuthorizedClientManager.class));
    return factoryBean;
  }
}
