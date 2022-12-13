package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.web.reactive.function.client.WebClient;

import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsWebSecurity;

@WebMvcTest(controllers = UiController.class)
@AutoConfigureAddonsWebSecurity
@Import(WebSecurityConfig.class)
class UiControllerTest {

	@Autowired
	MockMvcSupport mockMvc;
	
	@MockBean WebClient webClient;
	
	@MockBean OAuth2AuthorizedClientService authorizedClientService;

	@Test
	void whenAnonymousThenRedirectToLogin() throws Exception {
		mockMvc.get("/ui").andExpect(status().is3xxRedirection());
	}

}
