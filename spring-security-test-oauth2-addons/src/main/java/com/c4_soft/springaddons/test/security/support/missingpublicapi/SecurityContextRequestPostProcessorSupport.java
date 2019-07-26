package com.c4_soft.springaddons.test.security.support.missingpublicapi;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.web.support.WebTestUtils;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * Not visible in springframework (and method not static)
 */
public class SecurityContextRequestPostProcessorSupport {

	/**
	 * Saves the specified {@link Authentication} into an empty
	 * {@link SecurityContext} using the {@link SecurityContextRepository}.
	 *
	 * @param authentication the {@link Authentication} to save
	 * @param request the {@link HttpServletRequest} to use
	 */
	public static final void save(Authentication authentication, HttpServletRequest request) {
		final SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(authentication);
		save(securityContext, request);
	}

	/**
	 * Saves the {@link SecurityContext} using the {@link SecurityContextRepository}
	 *
	 * @param securityContext the {@link SecurityContext} to save
	 * @param request the {@link HttpServletRequest} to use
	 */
	public static final void save(SecurityContext securityContext, HttpServletRequest request) {
		SecurityContextRepository securityContextRepository = WebTestUtils
				.getSecurityContextRepository(request);
		final boolean isTestRepository = securityContextRepository instanceof SecurityContextRequestPostProcessorSupport.TestSecurityContextRepository;
		if (!isTestRepository) {
			securityContextRepository = new TestSecurityContextRepository(
					securityContextRepository);
			WebTestUtils.setSecurityContextRepository(request,
					securityContextRepository);
		}

		HttpServletResponse response = new MockHttpServletResponse();

		final HttpRequestResponseHolder requestResponseHolder = new HttpRequestResponseHolder(
				request, response);
		securityContextRepository.loadContext(requestResponseHolder);

		request = requestResponseHolder.getRequest();
		response = requestResponseHolder.getResponse();

		securityContextRepository.saveContext(securityContext, request, response);
	}

	/**
	 * Used to wrap the SecurityContextRepository to provide support for testing in
	 * stateless mode
	 */
	public static class TestSecurityContextRepository implements SecurityContextRepository {
		private final static String ATTR_NAME = SecurityContextRequestPostProcessorSupport.TestSecurityContextRepository.class
				.getName().concat(".REPO");

		private final SecurityContextRepository delegate;

		private TestSecurityContextRepository(SecurityContextRepository delegate) {
			this.delegate = delegate;
		}

		@Override
		public SecurityContext loadContext(
				HttpRequestResponseHolder requestResponseHolder) {
			final SecurityContext result = getContext(requestResponseHolder.getRequest());
			// always load from the delegate to ensure the request/response in the
			// holder are updated
			// remember the SecurityContextRepository is used in many different
			// locations
			final SecurityContext delegateResult = this.delegate
					.loadContext(requestResponseHolder);
			return result == null ? delegateResult : result;
		}

		@Override
		public void saveContext(SecurityContext context, HttpServletRequest request,
				HttpServletResponse response) {
			request.setAttribute(ATTR_NAME, context);
			this.delegate.saveContext(context, request, response);
		}

		@Override
		public boolean containsContext(HttpServletRequest request) {
			return getContext(request) != null
					|| this.delegate.containsContext(request);
		}

		public static SecurityContext getContext(HttpServletRequest request) {
			return (SecurityContext) request.getAttribute(ATTR_NAME);
		}
	}
}