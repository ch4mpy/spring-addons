/*
 * Copyright 2020 Jérôme Wacongne
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
package com.c4_soft.springaddons.security.oauth2;

import java.io.Serializable;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Extract claims from JWT. Claims can be OpenID, but don not have to. All that is required is it implements Map&lt;String, Object&gt; &amp; Serializable.
 * 
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public interface SynchronizedJwt2ClaimSetConverter<T extends Map<String, Object> & Serializable> extends Converter<Jwt, T> {
}
