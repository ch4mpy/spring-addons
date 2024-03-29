/*
 * Copyright 2018 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */
package com.c4_soft.springaddons.test.support.web;

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