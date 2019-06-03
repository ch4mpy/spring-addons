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
package com.c4soft.oauth2.rfc6749;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public enum AuthenticationError {
	ACCESS_DENIED("access_denied"),
	INVALID_CLIENT("invalid_client"),
	INVALID_GRANT("invalid_grant"),
	INVALID_REQUEST("invalid_request"),
	INVALID_SCOPE("invalid_scope"),
	SERVER_ERROR("server_error"),
	TEMPORARILY_UNAVAILABLE("temporarily_unavailable"),
	UNAUTHORIZED_CLIENT("unauthorized_client"),
	UNSUPPORTED_GRANT_TYPE("unsupported_grant_type"),
	UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type");

	public final String value;

	AuthenticationError(String code){
		this.value = code;
	}

	@Override
	public String toString() {
		return value;
	}
}