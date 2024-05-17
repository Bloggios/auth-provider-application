/*
 * Copyright © 2023-2024 Bloggios
 * All rights reserved.
 * This software is the property of Rohit Parihar and is protected by copyright law.
 * The software, including its source code, documentation, and associated files, may not be used, copied, modified, distributed, or sublicensed without the express written consent of Rohit Parihar.
 * For licensing and usage inquiries, please contact Rohit Parihar at rohitparih@gmail.com, or you can also contact support@bloggios.com.
 * This software is provided as-is, and no warranties or guarantees are made regarding its fitness for any particular purpose or compatibility with any specific technology.
 * For license information and terms of use, please refer to the accompanying LICENSE file or visit http://www.apache.org/licenses/LICENSE-2.0.
 * Unauthorized use of this software may result in legal action and liability for damages.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.bloggios.auth.provider.authentication;

import com.bloggios.auth.provider.constants.ServiceConstants;
import com.bloggios.auth.provider.payload.response.JwtErrorResponse;
import com.bloggios.auth.provider.utils.JwtDecoderUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.lang.NonNullApi;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Collection;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.authentication
 * Created_on - 13 December-2023
 * Created_at - 22 : 48
 */

@Component
public class JwtTokenValidationFilter extends OncePerRequestFilter {

    private final JwtDecoderUtil jwtDecoderUtil;
    private final JwtDecoder jwtDecoder;

    public JwtTokenValidationFilter(
            JwtDecoderUtil jwtDecoderUtil,
            JwtDecoder jwtDecoder
    ) {
        this.jwtDecoderUtil = jwtDecoderUtil;
        this.jwtDecoder = jwtDecoder;
    }

    private void addAuthentication(HttpServletRequest request, String token) {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            UserPrincipal userPrincipal = new UserPrincipal();
            Collection<? extends GrantedAuthority> grantedAuthorities = jwtDecoderUtil.extractAuthorities(token);
            String userId = jwtDecoderUtil.extractUserId(token);
            userPrincipal.setUserId(userId);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userPrincipal, null, grantedAuthorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String breadcrumbId = extractBreadcrumbId(request);
            MDC.put(ServiceConstants.BREADCRUMB_ID, breadcrumbId);
            String token = extractToken(request);
            if (token != null) {
                try {
                    jwtDecoder.decode(token);
                } catch (JwtValidationException exception) {
                    Collection<OAuth2Error> errors = exception.getErrors();
                    boolean isExpired = false;
                    for (OAuth2Error error : errors) {
                        if (error.getDescription().contains("expired")) {
                            isExpired = true;
                            break;
                        }
                    }
                    response.setStatus(isExpired ? HttpStatus.FORBIDDEN.value() : HttpStatus.UNAUTHORIZED.value());
                    response.setContentType("application/json");
                    OutputStream output = response.getOutputStream();
                    ObjectMapper mapper = new ObjectMapper();
                    JwtErrorResponse jwtErrorResponse = JwtErrorResponse
                            .builder()
                            .message(isExpired ? "JWT token is Expired" : exception.getMessage())
                            .isExpired(isExpired)
                            .build();
                    mapper.writeValue(output, jwtErrorResponse);
                    output.flush();
                    return;
                } catch (BadJwtException exception) {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.setContentType("application/json");
                    OutputStream output = response.getOutputStream();
                    ObjectMapper mapper = new ObjectMapper();
                    JwtErrorResponse jwtErrorResponse = JwtErrorResponse
                            .builder()
                            .message(exception.getMessage())
                            .build();
                    mapper.writeValue(output, jwtErrorResponse);
                    output.flush();
                    return;
                }
                addAuthentication(request, token);
            }
            filterChain.doFilter(request, response);
        } finally {

        }
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader(ServiceConstants.AUTHORIZATION);
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }

    private String extractBreadcrumbId(HttpServletRequest request) {
        String breadcrumbId;
        if (StringUtils.hasText(request.getHeader(ServiceConstants.BREADCRUMB_ID))) {
            breadcrumbId = request.getHeader(ServiceConstants.BREADCRUMB_ID);
        } else {
            breadcrumbId = UUID.randomUUID().toString();
        }
        return breadcrumbId;
    }
}
