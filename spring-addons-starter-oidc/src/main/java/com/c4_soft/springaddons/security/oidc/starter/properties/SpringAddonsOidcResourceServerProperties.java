package com.c4_soft.springaddons.security.oidc.starter.properties;

import java.util.List;
import lombok.Data;

/**
 * Auto-configuration for an OAuth2 resource server Security(Web)FilterChain with
 * &#64;Order(LOWEST_PRECEDENCE). Typical use case is a REST API secured with access tokens. Default
 * configuration is as follow: no securityMatcher to process all the requests that were not
 * intercepted by higher &#64;Order Security(Web)FilterChains, no session, disabled CSRF protection,
 * and 401 to unauthorized requests.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Data
public class SpringAddonsOidcResourceServerProperties {

  /**
   * Resource server SecurityFilterChain bean and all its dependencies are instantiated only if
   * true.
   */
  private boolean enabled = true;

  /**
   * Path matchers for the routes accessible to anonymous requests
   */
  private List<String> permitAll = List.of();

  /**
   * Whether to disable sessions. It should remain true.
   */
  private boolean statlessSessions = true;

  /**
   * CSRF protection configuration for the auto-configured client filter-chain
   */
  private Csrf csrf = Csrf.DISABLE;

  /**
   * Fine grained CORS configuration
   * 
   * @deprecated use com.c4-soft.springaddons.oidc.cors instead
   */
  @Deprecated(forRemoval = true)
  private List<CorsProperties> cors = List.of();

}
