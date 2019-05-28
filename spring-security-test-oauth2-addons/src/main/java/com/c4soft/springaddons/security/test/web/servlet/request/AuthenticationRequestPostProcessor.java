package com.c4soft.springaddons.security.test.web.servlet.request;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import com.c4soft.springaddons.security.test.support.AuthenticationBuilder;
import com.c4soft.springaddons.security.test.support.missingpublicapi.SecurityContextRequestPostProcessorSupport;

public interface AuthenticationRequestPostProcessor<T extends Authentication> extends RequestPostProcessor, AuthenticationBuilder<T> {
	@Override
	default MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
		SecurityContextRequestPostProcessorSupport.save(build(), request);
		return request;
	}
}
