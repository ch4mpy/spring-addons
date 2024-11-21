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

import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.StringUtils;
import com.c4_soft.springaddons.security.oidc.ModifiableClaimSet;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;

/**
 * https://openid.net/specs/openid-connect-core-1_0.html
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OpenidClaimSetBuilder<T extends OpenidClaimSetBuilder<T>> extends ModifiableClaimSet {

  private static final long serialVersionUID = 8050195176203128543L;

  private String usernameClaim = StandardClaimNames.SUB;

  public OpenidClaimSetBuilder() {}

  public OpenidClaimSetBuilder(Map<String, Object> ptivateClaims) {
    super(ptivateClaims);
  }

  public OpenidClaimSet build() {
    return new OpenidClaimSet(this, usernameClaim);
  }

  @SuppressWarnings("unchecked")
  private T cast() {
    return (T) this;
  }

  public T usernameClaim(String usernameClaim) {
    this.usernameClaim = usernameClaim;
    return cast();
  }

  public T acr(String acr) {
    return setIfNonEmpty(IdTokenClaimNames.ACR, acr);
  }

  public T amr(List<String> amr) {
    return setIfNonEmpty(IdTokenClaimNames.AMR, amr);
  }

  public T audience(List<String> audience) {
    return setIfNonEmpty(IdTokenClaimNames.AUD, audience);
  }

  public T authTime(Instant authTime) {
    return setIfNonEmpty(IdTokenClaimNames.AUTH_TIME, authTime);
  }

  public T azp(String azp) {
    return setIfNonEmpty(IdTokenClaimNames.AZP, azp);
  }

  public T expiresAt(Instant expiresAt) {
    return setIfNonEmpty(IdTokenClaimNames.EXP, expiresAt);
  }

  public T issuedAt(Instant issuedAt) {
    return setIfNonEmpty(IdTokenClaimNames.IAT, issuedAt);
  }

  public T jwtId(String jti) {
    return setIfNonEmpty(JwtClaimNames.JTI, jti);
  }

  public T issuer(URL issuer) {
    return setIfNonEmpty(IdTokenClaimNames.ISS, issuer.toString());
  }

  public T nonce(String nonce) {
    return setIfNonEmpty(IdTokenClaimNames.NONCE, nonce);
  }

  public T notBefore(Instant nbf) {
    return setIfNonEmpty(JwtClaimNames.NBF, nbf);
  }

  public T accessTokenHash(String atHash) {
    return setIfNonEmpty(IdTokenClaimNames.AT_HASH, atHash);
  }

  public T authorizationCodeHash(String cHash) {
    return setIfNonEmpty(IdTokenClaimNames.C_HASH, cHash);
  }

  public T sessionState(String sessionState) {
    return setIfNonEmpty("session_state", sessionState);
  }

  public T subject(String subject) {
    return setIfNonEmpty(IdTokenClaimNames.SUB, subject);
  }

  public T name(String value) {
    return setIfNonEmpty(StandardClaimNames.NAME, value);
  }

  public T givenName(String value) {
    return setIfNonEmpty(StandardClaimNames.GIVEN_NAME, value);
  }

  public T familyName(String value) {
    return setIfNonEmpty(StandardClaimNames.FAMILY_NAME, value);
  }

  public T middleName(String value) {
    return setIfNonEmpty(StandardClaimNames.MIDDLE_NAME, value);
  }

  public T nickname(String value) {
    return setIfNonEmpty(StandardClaimNames.NICKNAME, value);
  }

  public T preferredUsername(String value) {
    return setIfNonEmpty(StandardClaimNames.PREFERRED_USERNAME, value);
  }

  public T profile(String value) {
    return setIfNonEmpty(StandardClaimNames.PROFILE, value);
  }

  public T picture(String value) {
    return setIfNonEmpty(StandardClaimNames.PICTURE, value);
  }

  public T website(String value) {
    return setIfNonEmpty(StandardClaimNames.WEBSITE, value);
  }

  public T email(String value) {
    return setIfNonEmpty(StandardClaimNames.EMAIL, value);
  }

  public T emailVerified(Boolean value) {
    return setIfNonEmpty(StandardClaimNames.EMAIL_VERIFIED, value);
  }

  public T gender(String value) {
    return setIfNonEmpty(StandardClaimNames.GENDER, value);
  }

  public T birthdate(String value) {
    return setIfNonEmpty(StandardClaimNames.BIRTHDATE, value);
  }

  public T zoneinfo(String value) {
    return setIfNonEmpty(StandardClaimNames.ZONEINFO, value);
  }

  public T locale(String value) {
    return setIfNonEmpty(StandardClaimNames.LOCALE, value);
  }

  public T phoneNumber(String value) {
    return setIfNonEmpty(StandardClaimNames.PHONE_NUMBER, value);
  }

  public T phoneNumberVerified(Boolean value) {
    return setIfNonEmpty(StandardClaimNames.PHONE_NUMBER_VERIFIED, value);
  }

  public T address(AddressClaim value) {
    if (value == null) {
      this.remove("address");
    } else {
      this.put("address", value);
    }
    return cast();
  }

  public T claims(Map<String, Object> claims) {
    this.putAll(claims);
    return cast();
  }

  public T privateClaims(Map<String, Object> claims) {
    return this.claims(claims);
  }

  public T otherClaims(Map<String, Object> claims) {
    return this.claims(claims);
  }

  public T updatedAt(Instant value) {
    return setIfNonEmpty("", value);
  }

  protected T setIfNonEmpty(String claimName, String claimValue) {
    if (StringUtils.hasText(claimValue)) {
      this.put(claimName, claimValue);
    } else {
      this.remove(claimName);
    }
    return cast();
  }

  protected T setIfNonEmpty(String claimName, Collection<String> claimValue) {
    if (claimValue == null || claimValue.isEmpty()) {
      this.remove(claimName);
    } else if (claimValue.isEmpty()) {
      this.setIfNonEmpty(claimName, claimValue.iterator().next());
    } else {
      this.put(claimName, claimValue);
    }
    return cast();
  }

  protected T setIfNonEmpty(String claimName, Instant claimValue) {
    if (claimValue == null) {
      this.remove(claimName);
    } else {
      this.put(claimName, claimValue.getEpochSecond());
    }
    return cast();
  }

  protected T setIfNonEmpty(String claimName, Boolean claimValue) {
    if (claimValue == null) {
      this.remove(claimName);
    } else {
      this.put(claimName, claimValue);
    }
    return cast();
  }

  public static final class AddressClaim extends ModifiableClaimSet {
    private static final long serialVersionUID = 28800769851008900L;

    public AddressClaim formatted(String value) {
      return setIfNonEmpty("formatted", value);
    }

    public AddressClaim streetAddress(String value) {
      return setIfNonEmpty("street_address", value);
    }

    public AddressClaim locality(String value) {
      return setIfNonEmpty("locality", value);
    }

    public AddressClaim region(String value) {
      return setIfNonEmpty("region", value);
    }

    public AddressClaim postalCode(String value) {
      return setIfNonEmpty("postal_code", value);
    }

    public AddressClaim country(String value) {
      return setIfNonEmpty("country", value);
    }

    private AddressClaim setIfNonEmpty(String claimName, String claimValue) {
      if (StringUtils.hasText(claimValue)) {
        this.put(claimName, claimValue);
      } else {
        this.remove(claimName);
      }
      return this;
    }
  }
}
