/*
 * Copyright 2013-2022 the original author or authors.
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

package org.springframework.cloud.gateway.filter.factory.jwt;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import org.springframework.util.StringUtils;

class JwtHelper {

	static String cleanupHeaderValue(String headerValue) {
		headerValue = headerValue.replaceFirst("^(?i)bearer", "");
		headerValue = headerValue.replaceAll("\\s+", "");

		return headerValue;
	}

	static Object getClaimValue(String headerValue, String claim) {
		if (!StringUtils.hasText(headerValue)) {
			return null;
		}
		try {
			JWT token = JWTParser.parse(headerValue);
			return token.getJWTClaimsSet().getClaim(claim);
		}
		catch (Exception e) {
			return null;
		}
	}
}
