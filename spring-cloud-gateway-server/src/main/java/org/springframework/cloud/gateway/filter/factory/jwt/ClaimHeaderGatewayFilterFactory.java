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

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.style.ToStringCreator;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.server.ServerWebExchange;

import static org.springframework.cloud.gateway.filter.factory.jwt.JwtHelper.cleanupHeaderValue;
import static org.springframework.cloud.gateway.filter.factory.jwt.JwtHelper.getClaimValue;
import static org.springframework.cloud.gateway.support.GatewayToStringStyler.filterToStringCreator;

public class ClaimHeaderGatewayFilterFactory
		extends AbstractGatewayFilterFactory<ClaimHeaderGatewayFilterFactory.Config> {

	private final Logger log = LoggerFactory.getLogger(ClaimHeaderGatewayFilterFactory.class);

	@Override
	public GatewayFilter apply(Config config) {
		return new GatewayFilter() {


			@Override
			public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
				return ReactiveSecurityContextHolder
						.getContext()
						.map(context -> {
							ServerWebExchange mutatedExchange = addClaimFromSessionToken(config,
									exchange,
									context.getAuthentication());
							return mutatedExchange != null ? mutatedExchange : exchange;
						})
						.switchIfEmpty(Mono.fromSupplier(() -> addClaimFromAuthorizationHeaderToken(exchange, config)))
						.flatMap(chain::filter);
			}

			@Override
			public String toString() {
				ToStringCreator toStringCreator = filterToStringCreator(
						ClaimHeaderGatewayFilterFactory.this);

				toStringCreator.append("claim", config.getClaim());
				toStringCreator.append("headerName", config.getHeaderName());

				return toStringCreator.toString();
			}

		};
	}

	@Override
	public String name() {
		return "ClaimHeader";
	}

	@Override
	public Config newConfig() {
		return new Config();
	}

	@Override
	public Class<Config> getConfigClass() {
		return Config.class;
	}

	@Override
	public List<String> shortcutFieldOrder() {
		return Arrays.asList("claim", "headerName");
	}

	private ServerWebExchange addClaimFromSessionToken(Config config, ServerWebExchange exchange,
													   Authentication authentication) {
		if (authentication instanceof JwtAuthenticationToken) {
			log.debug("Found JwtAuthenticationToken authentication object");

			return copyClaimToHeader(exchange,
					config,
					() -> ((JwtAuthenticationToken) authentication).getTokenAttributes()
																   .get(config.claim));
		}

		if (authentication instanceof OAuth2AuthenticationToken) {
			log.debug("Found OAuth2AuthenticationToken authentication object");

			return copyClaimToHeader(exchange,
					config,
					() -> ((OAuth2AuthenticationToken) authentication).getPrincipal()
																	  .getAttributes()
																	  .get(config.claim));
		}
		return null;
	}

	private ServerWebExchange addClaimFromAuthorizationHeaderToken(ServerWebExchange exchange, Config config) {

		Optional<String> authorizationHeader = exchange.getRequest()
													   .getHeaders()
													   .getOrDefault(HttpHeaders.AUTHORIZATION, Collections.emptyList())
													   .stream()
													   .findFirst();

		if (authorizationHeader.isPresent()) {
			return exchange.mutate()
						   .request(request -> request.headers(headers -> {
							   String cleanupHeaderValue = cleanupHeaderValue(authorizationHeader.get());
							   Object value = getClaimValue(cleanupHeaderValue, config.claim);

							   if (value != null) {
								   List<String> previousValues = headers.get(config.headerName);
								   log.debug("Found value for claim '{}', including into request headers",
										   config.claim);
								   headers.put(
										   config.headerName,
										   buildHeaderValue(addValueToList(previousValues, value)));
							   }
						   }))
						   .build();
		}

		return exchange;
	}

	private ServerWebExchange copyClaimToHeader(ServerWebExchange exchange, Config config,
												Supplier<Object> valueSupplier) {
		return exchange.mutate()
					   .request(request -> request
							   .headers(headers -> {
								   Object value = valueSupplier.get();

								   if (value != null) {
									   List<String> previousValues = headers.get(config.headerName);
									   log.debug(
											   "Found value for claim '{}', including into request headers",
											   config.claim);

									   headers.put(
											   config.headerName,
											   buildHeaderValue(addValueToList(previousValues, value)));
								   }
							   }))
					   .build();
	}

	private List<String> buildHeaderValue(Object value) {
		if (value instanceof Collection) {
			return ((Collection<?>) value).stream()
										  .map(this::mapSimpleValue)
										  .collect(Collectors.toList());
		}
		return List.of(mapSimpleValue(value));
	}

	private String mapSimpleValue(Object value) {
		if (value instanceof String) {
			return (String) value;
		}
		if (value instanceof Instant) {
			return String.valueOf(((Instant) value).getEpochSecond());
		}
		return value.toString();
	}

	private Collection<Object> addValueToList(List<String> previousValues, Object value) {
		if (previousValues == null)
			return (value instanceof Collection) ? (Collection<Object>) value : List.of(value);

		final ArrayList mergedValues = new ArrayList();
		if (value instanceof Collection) {
			mergedValues.addAll(previousValues);
			mergedValues.addAll((Collection) value);
		}
		else {
			mergedValues.add(value);

		}
		return mergedValues;
	}

	@Validated
	public static class Config {

		private String claim;

		private String headerName;

		public String getClaim() {
			return claim;
		}

		public void setClaim(String claim) {
			this.claim = claim;
		}

		public String getHeaderName() {
			return headerName;
		}

		public void setHeaderName(String headerName) {
			this.headerName = headerName;
		}

	}

}
