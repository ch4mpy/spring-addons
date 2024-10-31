/*
 * Copyright 2020 Jérôme Wacongne.
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
package com.c4_soft.springaddons.security.oauth2.test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidToken;

public class OAuthenticationTestingBuilder
    implements AuthenticationBuilder<OAuthentication<OpenidToken>> {

  protected final OpenidTokenBuilder tokenBuilder;
  private final Set<String> authorities;

  public OAuthenticationTestingBuilder() {
    this.tokenBuilder = new OpenidTokenBuilder().subject(Defaults.SUBJECT).name(Defaults.AUTH_NAME);
    this.authorities = new HashSet<>(Defaults.AUTHORITIES);
  }

  @Override
  public OAuthentication<OpenidToken> build() {
    return new OAuthentication<>(tokenBuilder.build(),
        authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet()));
  }

  public OAuthenticationTestingBuilder authorities(String... authorities) {
    this.authorities.clear();
    this.authorities.addAll(Arrays.asList(authorities));
    return this;
  }

  public OAuthenticationTestingBuilder token(Consumer<OpenidTokenBuilder> tokenBuilderConsumer) {
    tokenBuilderConsumer.accept(tokenBuilder);
    return this;
  }

  public OAuthenticationTestingBuilder bearerString(String bearerString) {
    this.tokenBuilder.tokenValue(bearerString);
    return this;
  }
}
