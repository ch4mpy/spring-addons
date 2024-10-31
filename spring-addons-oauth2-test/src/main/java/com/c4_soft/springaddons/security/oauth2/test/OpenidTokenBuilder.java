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
package com.c4_soft.springaddons.security.oauth2.test;

import com.c4_soft.springaddons.security.oidc.OpenidToken;

/**
 * https://openid.net/specs/openid-connect-core-1_0.html
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OpenidTokenBuilder extends OpenidClaimSetBuilder<OpenidTokenBuilder> {
  private static final long serialVersionUID = -1742198682772227737L;

  private String tokenValue = "machin.truc.bidule";

  public OpenidTokenBuilder tokenValue(String tokenValue) {
    this.tokenValue = tokenValue;
    return this;
  }

  @Override
  public OpenidToken build() {
    return new OpenidToken(super.build(), tokenValue);
  }
}
