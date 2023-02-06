package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockBearerTokenAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AddonsWebmvcTestConf;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;

/**
 * <h2>Integration-test for the application</h2>
 * <p>
 * Nothing but the HTTP request is mocked: real controllers, services,
 * repositories and other components are wired together.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ImportAutoConfiguration({ AddonsWebmvcTestConf.class })
class SampleApiIntegrationTest {

    @Autowired
    MockMvcSupport api;

    @Test
    void givenRequestIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
        api.get("/greet").andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockBearerTokenAuthentication()
    void givenUserIsAuthenticated_whenGetGreet_thenOk() throws Exception {
        api.get("/greet").andExpect(content().string("Hello user! You are granted with []."));
    }

    @Test
    @WithMockBearerTokenAuthentication(authorities = "ROLE_AUTHORIZED_PERSONNEL", attributes = @OpenIdClaims(preferredUsername = "Ch4mpy"))
    void givenUserIsCh4mpy_whenGetGreet_thenOk() throws Exception {
        api.get("/greet")
                .andExpect(content().string("Hello Ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL]."));
    }

}
