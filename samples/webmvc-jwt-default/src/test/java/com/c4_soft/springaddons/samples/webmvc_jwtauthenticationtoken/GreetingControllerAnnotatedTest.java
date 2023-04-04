/*
 * Copyright 2019 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import com.c4_soft.springaddons.security.oauth2.test.annotations.Claims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.DoubleClaim;
import com.c4_soft.springaddons.security.oauth2.test.annotations.IntClaim;
import com.c4_soft.springaddons.security.oauth2.test.annotations.JsonObjectArrayClaim;
import com.c4_soft.springaddons.security.oauth2.test.annotations.JsonObjectClaim;
import com.c4_soft.springaddons.security.oauth2.test.annotations.LongClaim;
import com.c4_soft.springaddons.security.oauth2.test.annotations.NestedClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.StringArrayClaim;
import com.c4_soft.springaddons.security.oauth2.test.annotations.StringClaim;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsWebSecurity;

/**
 * <h2>Unit-test a secured controller</h2>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */

@WebMvcTest(GreetingController.class) // Use WebFluxTest or WebMvcTest
@AutoConfigureAddonsWebSecurity // If your web-security depends on it, setup spring-addons security
@Import({ SecurityConfig.class }) // Import your web-security configuration
class GreetingControllerAnnotatedTest {

    // Mock controller injected dependencies
    @MockBean
    private MessageService messageService;

    @Autowired
    MockMvcSupport api;

    @BeforeEach
	public void setUp() {
		when(messageService.greet(any())).thenAnswer(invocation -> {
			final JwtAuthenticationToken auth = invocation.getArgument(0, JwtAuthenticationToken.class);
			return String.format("Hello %s! You are granted with %s.", auth.getName(), auth.getAuthorities());
		});
		when(messageService.getSecret()).thenReturn("Secret message");
	}

    @Test
    void givenRequestIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
        api.get("/greet").andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class, authorities = "ROLE_AUTHORIZED_PERSONNEL")
    void givenUserHasMockedAuthenticated_whenGetGreet_thenOk() throws Exception {
        api.get("/greet").andExpect(content().string("Hello user! You are granted with [ROLE_AUTHORIZED_PERSONNEL]."));
    }

    @Test
    @WithMockJwtAuth()
    void givenUserIsAuthenticated_whenGetGreet_thenOk() throws Exception {
        api.get("/greet").andExpect(content().string("Hello user! You are granted with []."));
    }

    @Test
    @WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class, name = "Ch4mpy", authorities = "ROLE_AUTHORIZED_PERSONNEL")
    void givenUserIsMockedAsCh4mpy_whenGetGreet_thenOk() throws Exception {
        api.get("/greet")
                .andExpect(content().string("Hello Ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL]."));
    }

    @Test
    @WithMockJwtAuth(authorities = "ROLE_AUTHORIZED_PERSONNEL", claims = @OpenIdClaims(sub = "Ch4mpy"))
    void givenUserIsCh4mpy_whenGetGreet_thenOk() throws Exception {
        api.get("/greet")
                .andExpect(content().string("Hello Ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL]."));
    }

    @Test
    @WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class)
    void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenForbidden() throws Exception {
        api.get("/secured-route").andExpect(status().isForbidden());
    }

    @Test
    @WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class, authorities = "ROLE_AUTHORIZED_PERSONNEL")
    void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenOk() throws Exception {
        api.get("/secured-route").andExpect(status().isOk());
    }

    @Test
    @WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class)
    void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenForbidden() throws Exception {
        api.get("/secured-method").andExpect(status().isForbidden());
    }

    @Test
    @WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class, authorities = "ROLE_AUTHORIZED_PERSONNEL")
    void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenOk() throws Exception {
        api.get("/secured-method").andExpect(status().isOk());
    }

    // @formatter:off
    static final String obj1 = """
{
  "prop1_1": {
    "nested1_1_1": "value1"
  },
  "prop1_2": {
    "nested1_2_1": 121
  },
}""";
    static final String obj2 = """
{
  "prop2_1": {
    "nested2_1_1": {
      "nested2_1_1_1": 2111
    }
  }
}""";
    static final String obj3 = """
{
  "prop1_1": {
    "nested1_1_1": "value1"
  },
  "prop1_2": {
    "nested1_2_1": 221
  },
}""";
    static final String obj4 = """
{
"prop2_1": {
  "nested2_1_1": "value2"
},
"prop2_2": {
  "nested2_2_1": 221
},
}""";

    @Test
    @WithMockJwtAuth(authorities = "ROLE_AUTHORIZED_PERSONNEL", claims = @OpenIdClaims(sub = "Ch4mpy", otherClaims = @Claims(
            intClaims = { @IntClaim(name = "int1", value = 42), @IntClaim(name = "int2", value = 51) },
            longClaims = { @LongClaim(name = "long1", value = 42), @LongClaim(name = "long2", value = 51) },
            doubleClaims = { @DoubleClaim(name = "double1", value = 4.2), @DoubleClaim(name = "double2", value = 5.1) },
            stringClaims = { @StringClaim(name = "str1", value = "String 1"), @StringClaim(name = "str2", value = "String 2") },
            uriClaims = { @StringClaim(name = "uri1", value = "https://localhost:8080/greet"), @StringClaim(name = "uri2", value = "https://localhost:4200/home#greet") },
            urlClaims = { @StringClaim(name = "url1", value = "https://localhost:8080/greet"), @StringClaim(name = "url2", value = "https://localhost:4200/home") },
            epochSecondClaims = { @IntClaim(name = "epoch1", value = 1670978400), @IntClaim(name = "epoch2", value = 1680648172)},
            dateClaims = { @StringClaim(name = "date1", value = "2022-12-14T00:40:00.000+00:00"), @StringClaim(name = "date1", value = "2023-04-04T00:42:00.000+00:00") },
            stringArrayClaims = { @StringArrayClaim(name = "strArr1", value = { "a", "b", "c" }), @StringArrayClaim(name = "strArr2", value = { "D", "E", "F" }) },
            jsonObjectClaims = { @JsonObjectClaim(name = "obj1", value = obj1), @JsonObjectClaim(name = "obj2", value = obj2)},
            jsonObjectArrayClaims = @JsonObjectArrayClaim(name = "objArr1", value = { obj3, obj4}),
            nestedClaims = { @NestedClaims(
                    name = "https://c4-soft.com/spring-addons",
                    intClaims = { @IntClaim(name = "nested_int1", value = 42), @IntClaim(name = "nested_int2", value = 51) },
                    longClaims = { @LongClaim(name = "nested_long1", value = 42), @LongClaim(name = "nested_long2", value = 51) },
                    doubleClaims = { @DoubleClaim(name = "nested_double1", value = 4.2), @DoubleClaim(name = "nested_double2", value = 5.1) },
                    stringClaims = { @StringClaim(name = "nested_str1", value = "String 1"), @StringClaim(name = "nested_str2", value = "String 2") },
                    uriClaims = { @StringClaim(name = "nested_uri1", value = "https://localhost:8080/greet"), @StringClaim(name = "nested_uri2", value = "https://localhost:4200/home#greet") },
                    urlClaims = { @StringClaim(name = "nested_url1", value = "https://localhost:8080/greet"), @StringClaim(name = "nested_url2", value = "https://localhost:4200/home") },
                    epochSecondClaims = { @IntClaim(name = "nested_epoch1", value = 1670978400), @IntClaim(name = "nested_epoch2", value = 1680648172)},
                    dateClaims = { @StringClaim(name = "nested_date1", value = "2022-12-14T00:40:00.000+00:00"), @StringClaim(name = "nested_date1", value = "2023-04-04T00:42:00.000+00:00") },
                    stringArrayClaims = { @StringArrayClaim(name = "nested_strArr1", value = { "a", "b", "c" }), @StringArrayClaim(name = "nested_strArr2", value = { "D", "E", "F" }) },
                    jsonObjectClaims = { @JsonObjectClaim(name = "nested_obj1", value = obj1), @JsonObjectClaim(name = "nested_obj2", value = obj2)},
            jsonObjectArrayClaims = @JsonObjectArrayClaim(name = "nested_objArr1", value = { obj3, obj4}))})))
    // @formatter:on
    void givenUserIsAuthenticated_whenGetClaims_thenOk() throws Exception {
        api.get("/claims").andExpect(status().isOk()).andExpect(content().string(
                "{\"sub\":\"Ch4mpy\",\"objArr1\":[{\"prop1_1\":{\"nested1_1_1\":\"value1\"},\"prop1_2\":{\"nested1_2_1\":221}},{\"prop2_2\":{\"nested2_2_1\":221},\"prop2_1\":{\"nested2_1_1\":\"value2\"}}],\"strArr1\":[\"a\",\"b\",\"c\"],\"strArr2\":[\"D\",\"E\",\"F\"],\"preferred_username\":\"user\",\"long2\":51,\"int2\":51,\"int1\":42,\"long1\":42,\"url1\":\"https://localhost:8080/greet\",\"url2\":\"https://localhost:4200/home\",\"str1\":\"String 1\",\"str2\":\"String 2\",\"address\":{},\"email_verified\":false,\"obj2\":{\"prop2_1\":{\"nested2_1_1\":{\"nested2_1_1_1\":2111}}},\"obj1\":{\"prop1_1\":{\"nested1_1_1\":\"value1\"},\"prop1_2\":{\"nested1_2_1\":121}},\"phone_number_verified\":false,\"date1\":\"2023-04-04T00:42:00.000+00:00\",\"https://c4-soft.com/spring-addons\":{\"nested_int1\":42,\"nested_int2\":51,\"nested_str2\":\"String 2\",\"nested_str1\":\"String 1\",\"nested_objArr1\":[{\"prop1_1\":{\"nested1_1_1\":\"value1\"},\"prop1_2\":{\"nested1_2_1\":221}},{\"prop2_2\":{\"nested2_2_1\":221},\"prop2_1\":{\"nested2_1_1\":\"value2\"}}],\"nested_strArr1\":[\"a\",\"b\",\"c\"],\"nested_obj2\":{\"prop2_1\":{\"nested2_1_1\":{\"nested2_1_1_1\":2111}}},\"nested_strArr2\":[\"D\",\"E\",\"F\"],\"nested_obj1\":{\"prop1_1\":{\"nested1_1_1\":\"value1\"},\"prop1_2\":{\"nested1_2_1\":121}},\"nested_double2\":5.1,\"nested_double1\":4.2,\"nested_epoch2\":\"2023-04-04T22:42:52.000+00:00\",\"nested_epoch1\":\"2022-12-14T00:40:00.000+00:00\",\"nested_long2\":51,\"nested_long1\":42,\"nested_url1\":\"https://localhost:8080/greet\",\"nested_url2\":\"https://localhost:4200/home\",\"nested_date1\":\"2023-04-04T00:42:00.000+00:00\",\"nested_uri1\":\"https://localhost:8080/greet\",\"nested_uri2\":\"https://localhost:4200/home#greet\"},\"uri2\":\"https://localhost:4200/home#greet\",\"uri1\":\"https://localhost:8080/greet\",\"double2\":5.1,\"double1\":4.2,\"epoch2\":\"2023-04-04T22:42:52.000+00:00\",\"epoch1\":\"2022-12-14T00:40:00.000+00:00\"}"));
    }
}
