/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.c4_soft.oauth2.rfc6749.dto;

import java.io.Serializable;
import java.net.URI;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import com.c4_soft.oauth2.rfc6749.AuthenticationError;

/**
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 * @deprecated for illustration purpose only (useless for now)
 */
@Deprecated
public class ErrorResponseDto implements Serializable {
	private static final long serialVersionUID = 562915804003429556L;

	private final String error;

	@Nullable
	private final String errorDescription;

	@Nullable
	private final String errorUri;

	@Nullable
	private final String state;

	public ErrorResponseDto(String error, @Nullable String errorDescription, @Nullable String errorUri, @Nullable String state) {
		super();
		Assert.hasText(error, "error must be non empty");
		this.error = error;
		this.errorDescription = errorDescription;
		this.errorUri = errorUri;
		this.state = state;
	}

	public ErrorResponseDto(String error) {
		this(error, null, null, null);
	}

	public String getError() {
		return error;
	}

	public String getErrorDescription() {
		return errorDescription;
	}

	public String getErrorUri() {
		return errorUri;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {
		private String error;
		private String errorDescription;
		private String errorUri;
		private String state;

		public Builder error(AuthenticationError error) {
			this.error = error.value;
			return this;
		}

		public Builder errorDescription(String errorDescription) {
			this.errorDescription = errorDescription;
			return this;
		}

		public Builder errorUri(URI errorUri) {
			if(errorUri == null) {
				this.errorUri = null;
			} else {
				this.errorUri = errorUri.toString();
			}
			return this;
		}

		public Builder state(String state) {
			this.state = state;
			return this;
		}

		public ErrorResponseDto build() {
			return new ErrorResponseDto(error, errorDescription, errorUri, state);
		}
	}
}
