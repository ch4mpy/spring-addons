package com.c4_soft.springaddons.rest.synchronised;

import org.springframework.context.ApplicationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import com.c4_soft.springaddons.rest.AbstractWebClientBuilderFactoryBean;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties;
import com.c4_soft.springaddons.rest.SpringAddonsWebClientHttpServiceGroupConfigurer;

/**
 * Servlet stack variant: backs {@code WebClient} {@code @ImportHttpServices} groups (a servlet
 * app opting a client into {@code type: WEB_CLIENT}) with an auto-configured client, using an
 * {@link OAuth2AuthorizedClientManager} and a {@link ClientRegistrationRepository} to build the
 * OAuth2 authorization filter function when needed.
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class SpringAddonsServletWebClientHttpServiceGroupConfigurer
    extends SpringAddonsWebClientHttpServiceGroupConfigurer {

  public SpringAddonsServletWebClientHttpServiceGroupConfigurer(
      SpringAddonsRestProperties restProperties, ApplicationContext applicationContext) {
    super(restProperties, applicationContext);
  }

  @Override
  protected AbstractWebClientBuilderFactoryBean newFactoryBean() {
    final var factoryBean = new ServletWebClientBuilderFactoryBean();
    factoryBean.setAuthorizedClientManager(resolve(OAuth2AuthorizedClientManager.class));
    factoryBean.setClientRegistrationRepository(resolve(ClientRegistrationRepository.class));
    return factoryBean;
  }
}
