package ${package}.exceptions;

import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.reactive.result.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class CustomExceptionHandler extends ResponseEntityExceptionHandler {
	@ResponseStatus(HttpStatus.NOT_FOUND)
	@ExceptionHandler(ResourceNotFoundException.class)
	protected void handleResourceNotFound(ResourceNotFoundException ex, WebRequest request) {
		logger.info(ex.getMessage());
	}

	@ResponseStatus(HttpStatus.I_AM_A_TEAPOT)
	@ExceptionHandler(MethodArgumentNotValidException.class)
	protected void handleValidationException(MethodArgumentNotValidException ex, WebRequest request) {
		final String msg = "Payload validation failure:"
				+ ex.getBindingResult().getAllErrors().stream().map(ObjectError::toString).collect(Collectors.joining("\n  * ", "\n  * ", ""));
		logger.info(msg);
	}
}
