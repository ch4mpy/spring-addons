package com.c4soft.springaddons.tutorials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.net.URL;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClient.RequestHeadersUriSpec;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOAuth2Login;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsWebSecurity;

import reactor.core.publisher.Mono;

@WebMvcTest(controllers = UiController.class)
@AutoConfigureAddonsWebSecurity
@Import({ WebSecurityConfig.class, ResourceServerWithUiProperties.class })
class UiControllerTest {

	@Autowired
	MockMvcSupport mockMvc;

	@MockBean
	WebClient webClient;

	@MockBean
	OAuth2AuthorizedClientService authorizedClientService;

	@Autowired
	ResourceServerWithUiProperties props;

	@BeforeEach
	public void setUp() throws Exception {
		props.setApiHost(new URL("https://localhost:8080"));
	}

	@Test
	void givenUserIsAnonymous_whenGetUi_thenRedirectedToLogin() throws Exception {
		mockMvc.get("/ui").andExpect(status().is3xxRedirection());
	}

	@SuppressWarnings("unchecked")
	@Test
	@WithOAuth2Login
	void givenUserIsAuthenticated_whenGetUiGreet_thenOk() throws Exception {
		final var getSpec = mock(RequestHeadersUriSpec.class);
		final var uriSpec = mock(RequestHeadersUriSpec.class);
		final var attributesSpec = mock(RequestHeadersUriSpec.class);
		when(webClient.get()).thenReturn(getSpec);
		when(getSpec.uri(any(URI.class))).thenReturn(uriSpec);
		when(uriSpec.attributes(any())).thenReturn(attributesSpec);
		when(attributesSpec.exchangeToMono(any())).thenReturn(Mono.just(ResponseEntity.ok("Hello test!")));

		final var actual = mockMvc.get("/ui/greet").andExpect(status().isOk()).andReturn().getModelAndView();
		assertEquals("greet", actual.getViewName());
		assertEquals("Hello test!", actual.getModel().get("msg"));
	}

}
