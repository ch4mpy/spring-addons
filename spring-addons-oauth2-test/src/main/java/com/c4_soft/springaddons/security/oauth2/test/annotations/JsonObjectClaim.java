/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */

package com.c4_soft.springaddons.security.oauth2.test.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface JsonObjectClaim {
	String name();

	String value();

	static final class Support {

		private Support() {
		}

		public static Object parse(JsonObjectClaim claim) {
			if (claim == null) {
				return null;
			}
			try {
				return new JSONParser(JSONParser.MODE_PERMISSIVE).parse(claim.value());
			} catch (final ParseException e) {
				throw new InvalidJsonException(e);
			}
		}

	}
}
