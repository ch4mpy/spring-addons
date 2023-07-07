package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithAnonymousUser;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOpaqueToken;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AutoConfigureAddonsWebmvcResourceServerSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.MockMvcSupport;

@WebMvcTest(controllers = GreetingController.class)
@AutoConfigureAddonsWebmvcResourceServerSecurity
@Import(WebSecurityConfig.class)
class GreetingControllerTest {

	@Autowired
	MockMvcSupport mockMvc;

	// @formatter:off
    @Test
    @WithOpaqueToken("ch4mp.json")
	void givenUserIsGrantedWithNice_whenGreet_thenOk() throws Exception {
		mockMvc.get("/greet")
		    .andExpect(status().isOk())
		    .andExpect(jsonPath("$.body").value("Hi ch4mp! You are granted with: [NICE, AUTHOR, ROLE_AUTHORIZED_PERSONNEL]."));
	}
    // @formatter:on

	@Test
	@WithOpaqueToken("tonton-pirate.json")
	void givenUserIsNotGrantedWithNice_whenGreet_thenForbidden() throws Exception {
		mockMvc.get("/greet").andExpect(status().isForbidden());
	}

	@Test
	@WithAnonymousUser
	void givenRequestIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
		mockMvc.get("/greet").andExpect(status().isUnauthorized());
	}

}
