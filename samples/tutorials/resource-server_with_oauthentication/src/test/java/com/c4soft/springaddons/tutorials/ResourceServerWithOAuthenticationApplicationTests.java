package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenId;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AddonsWebmvcTestConf;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ImportAutoConfiguration({ AddonsWebmvcTestConf.class })
class ResourceServerWithOAuthenticationApplicationTests {
    @Autowired
    MockMvcSupport api;

    @Test
    void givenRequestIsAnonymous_whenGetActuatorHealthLiveness_thenOk() throws Exception {
        api.get("/actuator/health").andExpect(status().isOk()).andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void givenRequestIsAnonymous_whenGetActuatorHealthReadiness_thenOk() throws Exception {
        api.get("/actuator/health/readiness").andExpect(status().isOk());
    }

    @Test
    void givenRequestIsAnonymous_whenGetActuator_thenUnauthorized() throws Exception {
        api.get("/actuator").andExpect(status().isUnauthorized());
    }

    @Test
    @OpenId("OBSERVABILITY:read")
    void givenUserIsGrantedWithObservabilityRead_whenGetActuator_thenOk() throws Exception {
        api.get("/actuator").andExpect(status().isOk());
    }

    @Test
    @OpenId("OBSERVABILITY:write")
    void givenUserIsGrantedWithObservabilityWrite_whenPostActuatorShutdown_thenOk() throws Exception {
        api.post(Map.of("configuredLevel", "debug"), "/actuator/loggers/com.c4soft")
                .andExpect(status().is2xxSuccessful());
    }

    @Test
    @OpenId("OBSERVABILITY:read")
    void givenUserIsNotGrantedWithObservabilityWrite_whenPostActuatorShutdown_thenForbidden() throws Exception {
        api.post(Map.of("configuredLevel", "debug"), "/actuator/loggers/com.c4soft").andExpect(status().isForbidden());
    }

    @Test
    @OpenId(authorities = { "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
    void givenUserIsAuthenticated_whenGreet_thenOk() throws Exception {
        api.get("/greet").andExpect(status().isOk())
                .andExpect(content().string("Hi Tonton Pirate! You are granted with: [AUTHOR]."));
    }

    @Test
    void givenRequestIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
        api.get("/greet").andExpect(status().isUnauthorized());
    }

    @Test
    @OpenId(authorities = { "NICE", "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
    void givenUserIsGrantedWithNice_whenGetNice_thenOk() throws Exception {
        api.get("/nice").andExpect(status().isOk())
                .andExpect(content().string("Dear Tonton Pirate! You are granted with: [NICE, AUTHOR]."));
    }

    @Test
    @OpenId(authorities = { "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
    void givenUserIsNotGrantedWithNice_whenGetNice_thenForbidden() throws Exception {
        api.get("/nice").andExpect(status().isForbidden());
    }

    @Test
    void givenRequestIsAnonymous_whenGetNice_thenUnauthorized() throws Exception {
        api.get("/nice").andExpect(status().isUnauthorized());
    }
}
