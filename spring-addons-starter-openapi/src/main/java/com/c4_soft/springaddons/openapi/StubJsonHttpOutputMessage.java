package com.c4_soft.springaddons.openapi;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.util.MultiValueMapAdapter;

class StubJsonHttpOutputMessage implements HttpOutputMessage {
	@SuppressWarnings("null")
	private static final @NonNull HttpHeaders HEADERS =
			new HttpHeaders(new MultiValueMapAdapter<>(Map.of(HttpHeaders.CONTENT_TYPE, List.of(MediaType.TEXT_PLAIN.toString()))));

	private final @NonNull ByteArrayOutputStream body = new ByteArrayOutputStream();

	@Override
	public @NonNull HttpHeaders getHeaders() {
		return HEADERS;
	}

	@Override
	public @NonNull OutputStream getBody() throws IOException {
		return body;
	}
}