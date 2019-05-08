package org.springframework.security.test.web.servlet.request;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.support.AuthenticationBuilder;
import org.springframework.security.test.support.missingpublicapi.SecurityContextRequestPostProcessorSupport;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

public interface AuthenticationRequestPostProcessor<T extends Authentication> extends RequestPostProcessor, AuthenticationBuilder<T> {
	@Override
	default MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
		SecurityContextRequestPostProcessorSupport.save(build(), request);
		return request;
	}
}
