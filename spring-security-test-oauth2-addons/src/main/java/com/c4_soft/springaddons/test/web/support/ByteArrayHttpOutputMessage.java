package com.c4_soft.springaddons.test.web.support;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpOutputMessage;

public final class ByteArrayHttpOutputMessage implements HttpOutputMessage {
	public final ByteArrayOutputStream out = new ByteArrayOutputStream();
	public final HttpHeaders headers = new HttpHeaders();

	@Override
	public OutputStream getBody() {
		return out;
	}

	@Override
	public HttpHeaders getHeaders() {
		return headers;
	}
}