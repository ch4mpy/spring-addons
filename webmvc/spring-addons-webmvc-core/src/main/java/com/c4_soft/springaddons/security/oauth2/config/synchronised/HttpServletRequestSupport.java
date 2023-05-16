package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.util.List;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.StreamSupport;

import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
 * <p>
 * Support class to statically access current request.
 * </p>
 * <p>
 * It is mainly intended at parsing additional headers when authorizing requests.
 * </p>
 *
 * @author ch4mp
 */
public class HttpServletRequestSupport {

	/**
	 * @return the request in current context
	 */
	public static Optional<HttpServletRequest> getRequest() {
		RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
		if (requestAttributes instanceof ServletRequestAttributes attr) {
			return Optional.ofNullable(attr.getRequest());
		}
		return Optional.empty();
	}

	public static Optional<HttpSession> getSession() {
		return getRequest().flatMap(req -> Optional.ofNullable(req.getSession()));
	}

	public static Object getSessionAttribute(String name) {
		return getSession().map(session -> session.getAttribute(name)).orElse(null);
	}

	public static void setSessionAttribute(String name, Object value) {
		getSession().ifPresent(session -> session.setAttribute(name, value));
	}

	/**
	 * @param  headerName                 name of the header to retrieve
	 * @return                            the unique value for the given header in current request
	 * @throws MissingHeaderException     if no non-empty value is found for that header
	 * @throws MultiValuedHeaderException if more than one non-empty value is found for that header
	 */
	public static String getUniqueRequestHeader(String headerName) throws MissingHeaderException, MultiValuedHeaderException {
		final var headers = getNonEmptyRequestHeaderValues(headerName);
		if (headers.size() < 1) {
			throw new MissingHeaderException(headerName);
		}
		if (headers.size() > 1) {
			throw new MultiValuedHeaderException(headerName);
		}
		return headers.get(0);
	}

	/**
	 * @param  headerName the name of the header to retrieve
	 * @return            a stream of non empty values for a given header from the request in current context
	 */
	public static List<String> getNonEmptyRequestHeaderValues(String headerName) {
		return getRequest().map(
				req -> StreamSupport.stream(Spliterators.spliteratorUnknownSize(req.getHeaders(headerName).asIterator(), Spliterator.ORDERED), false)
						.filter(StringUtils::hasLength).toList())
				.orElse(List.of());
	}

	@ResponseStatus(code = HttpStatus.UNAUTHORIZED)
	public static class MissingHeaderException extends RuntimeException {
		private static final long serialVersionUID = -4894061353773464761L;

		public MissingHeaderException(String headerName) {
			super(headerName + " is missing");
			assert (StringUtils.hasText(headerName));
		}
	}

	@ResponseStatus(code = HttpStatus.UNAUTHORIZED)
	public static class MultiValuedHeaderException extends RuntimeException {
		private static final long serialVersionUID = 1654993007508549674L;

		public MultiValuedHeaderException(String headerName) {
			super(headerName + " is not unique");
			assert (StringUtils.hasText(headerName));
		}
	}

	@ResponseStatus(code = HttpStatus.UNAUTHORIZED)
	public static class InvalidHeaderException extends RuntimeException {
		private static final long serialVersionUID = -6233252290377524340L;

		public InvalidHeaderException(String headerName) {
			super(headerName + " is not valid");
			assert (StringUtils.hasText(headerName));
		}
	}
}