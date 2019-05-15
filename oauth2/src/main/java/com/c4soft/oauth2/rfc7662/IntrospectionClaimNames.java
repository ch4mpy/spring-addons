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
package com.c4soft.oauth2.rfc7662;

/**
 * Claim names as defined by https://tools.ietf.org/html/rfc7662#section-2.2
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public enum IntrospectionClaimNames {
	ACTIVE("active"),
	SCOPE("scope"),
	CLIENT_ID("client_id"),
	USERNAME("username"),
	TOKEN_TYPE("token_type"),
	EXPIRES_AT("exp"),
	ISSUED_AT("iat"),
	NOT_BEFORE("nbf"),
	SUBJECT("sub"),
	AUDIENCE("aud"),
	ISSUER("iss"),
	JTI("jti");

	public final String value;

	IntrospectionClaimNames(String name){
		this.value = name;
	}

	@Override
	public String toString() {
		return value;
	}
}
