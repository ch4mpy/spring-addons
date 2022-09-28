package com.c4soft.springaddons.tutorials;

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

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ImportAutoConfiguration({ AddonsWebmvcTestConf.class })
class ResourceServerWithOAuthenticationApplicationTests {
	@Autowired
	MockMvcSupport api;

	@Test
	void whenUserIsNotAuthorizedThenUnauthorized() throws Exception {
		api.get("/greet").andExpect(status().isUnauthorized());
	}

	@Test
	@WithMockBearerTokenAuthentication()
	void whenUserIsNotGrantedWithNiceAuthorityThenForbidden() throws Exception {
		api.get("/greet").andExpect(status().isForbidden());
	}

	@Test
	@WithMockBearerTokenAuthentication(authorities = { "NICE", "AUTHOR" }, attributes = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void whenUserIsGrantedWithNiceAuthorityThenGreeted() throws Exception {
		api.get("/greet").andExpect(status().isOk()).andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE, AUTHOR]."));
	}

}
