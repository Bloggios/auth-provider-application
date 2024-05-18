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

package com.bloggios.auth.provider.oauth2;

import com.bloggios.auth.provider.authentication.UserPrincipal;
import com.bloggios.auth.provider.constants.ExceptionCodes;
import com.bloggios.auth.provider.constants.ServiceConstants;
import com.bloggios.auth.provider.exception.payloads.AuthenticationException;
import com.bloggios.auth.provider.properties.AuthServerProperties;
import com.bloggios.auth.provider.utils.CookieUtils;
import com.bloggios.auth.provider.utils.IpUtils;
import com.bloggios.auth.provider.utils.JwtTokenGenerator;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.time.LocalTime;
import java.util.Optional;

import static com.bloggios.auth.provider.constants.ServiceConstants.ORIGIN;
import static com.bloggios.auth.provider.oauth2.HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.oauth2
 * Created_on - 07 February-2024
 * Created_at - 18 : 10
 */

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthenticationSuccessHandler.class);

    private final JwtTokenGenerator jwtTokenGenerator;
    private final AuthServerProperties authServerProperties;
    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;
    private final Environment environment;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String origin = request.getHeader(ORIGIN);
        if (ObjectUtils.isEmpty(request.getHeader(ORIGIN))) {
            origin = ServiceConstants.LOCAL_ORIGIN;
        }
        String targetUrl = determineTargetUrl(request, response, authentication, origin);
        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to {}", targetUrl);
            return;
        }
        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication, String origin) {
        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);
        if(redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new AuthenticationException(ExceptionCodes.UNAUTHORIZED_REDIRECT_URI);
        }
        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());
        UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();
        String remoteAddress = IpUtils.getRemoteAddress(request);
        String accessToken = jwtTokenGenerator.generateAccessToken(
                authentication,
                getOrigin(request),
                false,
                remoteAddress
        );
        String refreshToken = jwtTokenGenerator.generateRefreshToken(
                authentication,
                getOrigin(request),
                remoteAddress
        );
        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("accessToken", accessToken)
                .queryParam("refreshToken", refreshToken)
                .queryParam("userId", principal.getUserId())
                .queryParam("loginTime", LocalTime.now())
                .build().toUriString();
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);
        return authServerProperties.getOAuth2().getAuthorizedRedirectUris()
                .stream()
                .anyMatch(authorizedRedirectUri -> {
                    URI authorizedURI = URI.create(authorizedRedirectUri);
                    if(authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                            && authorizedURI.getPort() == clientRedirectUri.getPort()) {
                        return true;
                    }
                    return false;
                });
    }

    private String getOrigin(HttpServletRequest httpServletRequest) {
        String origin = httpServletRequest.getHeader(ORIGIN);
        if (ObjectUtils.isEmpty(httpServletRequest.getHeader(ORIGIN))) {
            origin = ServiceConstants.LOCAL_ORIGIN;
        }
        return origin;
    }

    private boolean isLongToken(HttpServletRequest httpServletRequest) {
        String origin = httpServletRequest.getHeader(ORIGIN);
        return ObjectUtils.isEmpty(origin);
    }
}
