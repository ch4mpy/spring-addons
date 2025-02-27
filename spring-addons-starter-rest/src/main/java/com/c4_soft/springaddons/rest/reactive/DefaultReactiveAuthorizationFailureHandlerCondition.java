package com.c4_soft.springaddons.rest.reactive;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;

public class DefaultReactiveAuthorizationFailureHandlerCondition extends AllNestedConditions {

  DefaultReactiveAuthorizationFailureHandlerCondition() {
    super(ConfigurationPhase.REGISTER_BEAN);
  }

  @ConditionalOnMissingBean(ReactiveOAuth2AuthorizationFailureHandler.class)
  static class OAuth2AuthorizationFailureHandlerNotProvided {
  }

  @ConditionalOnBean(ServerOAuth2AuthorizedClientRepository.class)
  static class AuthorizedClientRepositoryProvided {
  }

}
