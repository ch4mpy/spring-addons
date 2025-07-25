package com.c4_soft.springaddons.openapi;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpOutputMessage;
import org.jspecify.annotations.NonNull;
import org.springframework.util.StreamUtils;

class MockHttpOutputMessage implements HttpOutputMessage {

	private final @NonNull HttpHeaders headers = new HttpHeaders();

	private final @NonNull ByteArrayOutputStream body = new ByteArrayOutputStream(1024);

	@Override
	public @NonNull HttpHeaders getHeaders() {
		return this.headers;
	}

	@Override
	public @NonNull OutputStream getBody() throws IOException {
		return this.body;
	}

	/**
	 * Return the body content as a byte array.
	 */
	public byte[] getBodyAsBytes() {
		return this.body.toByteArray();
	}

	/**
	 * Return the body content interpreted as a UTF-8 string.
	 */
	@SuppressWarnings("null")
	public String getBodyAsString() {
		return getBodyAsString(StandardCharsets.UTF_8);
	}

	/**
	 * Return the body content interpreted as a string using the supplied character set.
	 * 
	 * @param charset the charset to use to turn the body content into a String
	 */
	public String getBodyAsString(@NonNull Charset charset) {
		return StreamUtils.copyToString(this.body, charset);
	}

}