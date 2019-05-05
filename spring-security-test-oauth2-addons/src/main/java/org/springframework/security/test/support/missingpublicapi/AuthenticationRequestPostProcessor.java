package org.springframework.security.test.support.missingpublicapi;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

public class AuthenticationRequestPostProcessor<T extends Authentication> implements RequestPostProcessor {
	private final T authentication;

	public AuthenticationRequestPostProcessor(T authentication) {
		this.authentication = authentication;
	}

	@Override
	public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
		SecurityContextRequestPostProcessorSupport.save(this.authentication, request);
		return request;
	}
}
