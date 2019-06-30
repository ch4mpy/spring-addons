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
package com.c4soft.springaddons.sample.resource.config;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties("showcase")
public class ShowcaseResourceServerProperties {

	@Valid
	private final ShowcaseResourceServerProperties.Introspection introspection;

	@Valid
	private final ShowcaseResourceServerProperties.Management management;

	public ShowcaseResourceServerProperties() {
		super();
		introspection = new Introspection();
		management = new Management();
	}

	public ShowcaseResourceServerProperties.Introspection getIntrospection() {
		return introspection;
	}

	public ShowcaseResourceServerProperties.Management getManagement() {
		return management;
	}

	static class Introspection {

		@NotNull
		@Pattern(regexp = "^https://.+$")
		private String edpoint;

		@NotNull
		@Size(min = 1)
		private String clientId;

		@NotNull
		@Size(min = 1)
		private String password;


		public Introspection() {
			super();
		}

		public String getEdpoint() {
			return edpoint;
		}

		public void setEdpoint(String edpoint) {
			this.edpoint = edpoint;
		}

		public String getClientId() {
			return clientId;
		}

		public void setClientId(String clientId) {
			this.clientId = clientId;
		}

		public String getPassword() {
			return password;
		}

		public void setPassword(String password) {
			this.password = password;
		}
	}

	static class Management {

		@NotNull
		@Size(min = 1)
		private String username;

		@NotNull
		@Size(min = 1)
		private String password;

		public String getUsername() {
			return username;
		}

		public void setUsername(String username) {
			this.username = username;
		}

		public String getPassword() {
			return password;
		}

		public void setPassword(String password) {
			this.password = password;
		}

	}
}