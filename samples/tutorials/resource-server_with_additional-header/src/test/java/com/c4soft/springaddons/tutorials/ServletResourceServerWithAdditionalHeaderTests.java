package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AddonsWebmvcTestConf;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ImportAutoConfiguration({ AddonsWebmvcTestConf.class })
class ServletResourceServerWithAdditionalHeaderTests {
	@Autowired
	MockMvcSupport api;

	@Test
	void givenRequestIsAnonymous_whenGetActuatorHealthLiveness_thenOk() throws Exception {
		api.get("/actuator/health/liveness").andExpect(status().isOk()).andExpect(jsonPath("$.status").value("UP"));
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
	@WithMockAuthentication("OBSERVABILITY:read")
	void givenUserIsGrantedWithObservabilityRead_whenGetActuator_thenOk() throws Exception {
		api.get("/actuator").andExpect(status().isOk());
	}

	@Test
	@WithMockAuthentication("OBSERVABILITY:write")
	void givenUserIsGrantedWithObservabilityWrite_whenPostActuatorShutdown_thenOk() throws Exception {
		api.post(Map.of("configuredLevel", "debug"), "/actuator/loggers/com.c4soft").andExpect(status().is2xxSuccessful());
	}

	@Test
	@WithMockAuthentication("OBSERVABILITY:read")
	void givenUserIsNotGrantedWithObservabilityWrite_whenPostActuatorShutdown_thenForbidden() throws Exception {
		api.post(Map.of("configuredLevel", "debug"), "/actuator/loggers/com.c4soft").andExpect(status().isForbidden());
	}

	@Test
	@WithMyAuth(authorities = { "AUTHOR" }, idClaims = @OpenIdClaims(email = "ch4mp@c4-soft.com"))
	void givenUserIsAuthenticated_whenGreet_thenOk() throws Exception {
		api.get("/greet").andExpect(status().isOk()).andExpect(jsonPath("$.body").value("Hi ch4mp@c4-soft.com! You are granted with: [AUTHOR]."));
	}

	@Test
	void givenRequestIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
		api.get("/greet").andExpect(status().isUnauthorized());
	}
}
