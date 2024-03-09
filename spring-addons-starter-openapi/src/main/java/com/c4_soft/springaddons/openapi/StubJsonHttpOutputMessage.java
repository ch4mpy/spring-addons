package com.c4_soft.springaddons.openapi;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMapAdapter;

class StubJsonHttpOutputMessage implements HttpOutputMessage {
	private static final HttpHeaders HEADERS =
			new HttpHeaders(new MultiValueMapAdapter<>(Map.of(HttpHeaders.CONTENT_TYPE, List.of(MediaType.TEXT_PLAIN.toString()))));

	private ByteArrayOutputStream os = new ByteArrayOutputStream();

	@Override
	public HttpHeaders getHeaders() {
		return HEADERS;
	}

	@Override
	public OutputStream getBody() throws IOException {
		return os;
	}
}
