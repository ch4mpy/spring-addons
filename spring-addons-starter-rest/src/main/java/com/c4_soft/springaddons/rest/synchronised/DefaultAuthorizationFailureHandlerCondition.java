package com.c4_soft.springaddons.rest.synchronised;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

public class DefaultAuthorizationFailureHandlerCondition extends AllNestedConditions {

  DefaultAuthorizationFailureHandlerCondition() {
    super(ConfigurationPhase.REGISTER_BEAN);
  }

  @ConditionalOnMissingBean(OAuth2AuthorizationFailureHandler.class)
  static class OAuth2AuthorizationFailureHandlerNotProvided {
  }

  @ConditionalOnBean(OAuth2AuthorizedClientRepository.class)
  static class AuthorizedClientRepositoryProvided {
  }

}
