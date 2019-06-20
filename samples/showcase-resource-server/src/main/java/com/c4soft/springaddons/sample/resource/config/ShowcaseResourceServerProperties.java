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

import java.io.Serializable;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@ConfigurationProperties(prefix = "showcase")
@Validated
public class ShowcaseResourceServerProperties implements Serializable {
	private static final long serialVersionUID = 7421881747366496846L;

	private	boolean jwt;

	private	boolean jpa;

	@Valid
	private final ShowcaseResourceServerProperties.Introspection introspection;

	public ShowcaseResourceServerProperties() {
		super();
		introspection = new Introspection();
	}

	public boolean isJpa() {
		return jpa;
	}

	public void setJpa(boolean jpa) {
		this.jpa = jpa;
	}

	public boolean isJwt() {
		return jwt;
	}

	public void setJwt(boolean jwt) {
		this.jwt = jwt;
	}

	public ShowcaseResourceServerProperties.Introspection getIntrospection() {
		return introspection;
	}

	public static class Introspection implements Serializable {
		private static final long serialVersionUID = 2942831628138818591L;

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
}