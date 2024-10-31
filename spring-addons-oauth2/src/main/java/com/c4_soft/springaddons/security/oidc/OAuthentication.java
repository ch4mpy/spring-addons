/*
 * Copyright 2020 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package com.c4_soft.springaddons.security.oidc;

import java.io.Serializable;
import java.security.Principal;
import java.util.Collection;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.util.StringUtils;
import lombok.EqualsAndHashCode;

/**
 * @author ch4mp
 * @param <T> OpenidClaimSet or any specialization. See {@link }
 */
@EqualsAndHashCode(callSuper = true)
public class OAuthentication<T extends Map<String, Object> & Serializable & Principal & OAuth2Token>
    extends AbstractOAuth2TokenAuthenticationToken<T> implements OAuth2AuthenticatedPrincipal {
  private static final long serialVersionUID = 8193642106297738796L;
  /**
   * Claim-set associated with the access-token (attributes retrieved from the token or
   * introspection end-point)
   */
  private final T token;

  /**
   * @param token OAuth2Token of any-type (a {@link OpenidToken} or any sub-type is probably
   *        convenient)
   * @param authorities Granted authorities associated with this authentication instance
   */
  public OAuthentication(T token, Collection<? extends GrantedAuthority> authorities) {
    super(token, authorities);
    super.setAuthenticated(true);
    super.setDetails(token);
    this.token = token;
  }

  @Override
  public T getTokenAttributes() {
    return token;
  }

  @Override
  public void setDetails(Object details) {
    throw new RuntimeException("OAuthentication details are immutable");
  }

  @Override
  public void setAuthenticated(boolean isAuthenticated) {
    throw new RuntimeException("OAuthentication authentication status is immutable");
  }

  @Override
  public String getCredentials() {
    return token.getTokenValue();
  }

  @Override
  public String getName() {
    return getPrincipal().getName();
  }

  @Override
  public T getPrincipal() {
    return token;
  }

  @Override
  public T getAttributes() {
    return token;
  }

  public T getClaims() {
    return token;
  }

  public String getBearerHeader() {
    if (!StringUtils.hasText(token.getTokenValue())) {
      return null;
    }
    return String.format("Bearer %s", token.getTokenValue());
  }
}
