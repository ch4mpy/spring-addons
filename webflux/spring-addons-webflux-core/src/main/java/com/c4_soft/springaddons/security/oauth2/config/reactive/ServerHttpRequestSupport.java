package com.c4_soft.springaddons.security.oauth2.config.reactive;

import java.util.NoSuchElementException;

import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

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
public class ServerHttpRequestSupport {

	/**
	 * @return the request in current context
	 */
	public static Mono<ServerHttpRequest> getRequest() {
		return Mono.deferContextual(Mono::just).map(contextView -> contextView.get(ServerWebExchange.class).getRequest());
	}

	/**
	 * @param  headerName                name of the header to retrieve
	 * @return                              the unique value for the given header in current request
	 * @throws MissingHeaderException       if no non-empty value is found for that header
	 * @throws MultiValuedHeaderException more than one non-empty value is found for that header
	 */
	public static Mono<String> getUniqueHeader(String headerName) throws MissingHeaderException, MultiValuedHeaderException {
		try {
			return getNonEmptyHeaderValues(headerName).single();
		} catch (NoSuchElementException e) {
			throw new MissingHeaderException(headerName);
		} catch (IndexOutOfBoundsException e) {
			throw new MultiValuedHeaderException(headerName);
		}

	}

	/**
	 * @param  headerName the name of the header to retrieve
	 * @return            a stream of non empty values for a given header from the request in current context
	 */
	public static Flux<String> getNonEmptyHeaderValues(String headerName) {
		return getRequest().flatMapMany(req -> Flux.fromStream(req.getHeaders().getOrEmpty(headerName).stream().filter(StringUtils::hasLength)));
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