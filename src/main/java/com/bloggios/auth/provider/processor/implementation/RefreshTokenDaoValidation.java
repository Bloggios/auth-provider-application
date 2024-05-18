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

package com.bloggios.auth.provider.processor.implementation;

import com.bloggios.auth.provider.constants.EnvironmentConstants;
import com.bloggios.auth.provider.constants.ServiceConstants;
import com.bloggios.auth.provider.dao.implementation.pgsqlimplementation.RefreshTokenDao;
import com.bloggios.auth.provider.modal.RefreshTokenEntity;
import com.bloggios.auth.provider.payload.record.RefreshTokenDaoValidationRecord;
import com.bloggios.auth.provider.utils.IpUtils;
import com.bloggios.auth.provider.utils.JwtDecoderUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Objects;
import java.util.Optional;

/**
 * Owner - Rohit Parihar and Bloggios
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.validator.implementation.businessvalidator
 * Created_on - May 17 - 2024
 * Created_at - 12:50
 */

@Component
public class RefreshTokenDaoValidation {

    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenDaoValidation.class);

    private final RefreshTokenDao refreshTokenDao;
    private final Environment environment;
    private final JwtDecoderUtil jwtDecoderUtil;

    public RefreshTokenDaoValidation(
            RefreshTokenDao refreshTokenDao,
            Environment environment,
            JwtDecoderUtil jwtDecoderUtil) {
        this.refreshTokenDao = refreshTokenDao;
        this.environment = environment;
        this.jwtDecoderUtil = jwtDecoderUtil;
    }

    public Object validate(String refreshToken, HttpServletRequest httpServletRequest) {
        Optional<RefreshTokenEntity> byRefreshTokenOptional = refreshTokenDao.findByRefreshToken(refreshToken);
        if (byRefreshTokenOptional.isEmpty()) {
            return new RefreshTokenDaoValidationRecord(
                    getNullCookie(),
                    "No Refresh Token is present in Bloggios Servers"
            );
        }
        RefreshTokenEntity refreshTokenEntity = byRefreshTokenOptional.get();
        refreshTokenDao.deleteByEntity(refreshTokenEntity);
        String accessToken = extractAccessToken(httpServletRequest);
        if (Objects.isNull(accessToken)) {
            return new RefreshTokenDaoValidationRecord(
                    getNullCookie(),
                    "Access Token is not present in Authorization Header"
            );
        }
        if (!accessToken.equals(refreshTokenEntity.getAccessToken())) {
            return new RefreshTokenDaoValidationRecord(
                    getNullCookie(),
                    "Current Access Token is not matching with Old Access Token"
            );
        }
        String extractedUserId = jwtDecoderUtil.extractUserId(refreshToken);
        if (!refreshTokenEntity.getUserId().equals(extractedUserId)) {
            return new RefreshTokenDaoValidationRecord(
                    getNullCookie(),
                    "User Id is not matching from Token"
            );
        }
        String remoteAddress = jwtDecoderUtil.extractUserIp(refreshToken);
        String currentAddress = IpUtils.getRemoteAddress(httpServletRequest);
        if (
                !remoteAddress.equals(ServiceConstants.DEFAULT_IP) && !currentAddress.equals(ServiceConstants.DEFAULT_IP)
                && !remoteAddress.equals(currentAddress)
        ) {
            return new RefreshTokenDaoValidationRecord(
                    getNullCookie(),
                    "Not allowed to refresh access token from cross devices"
            );
        }
        logger.info("Validation complete for Refresh Token Dao");
        return null;
    }

    private Cookie getNullCookie() {
        String cookieName = environment.getProperty(EnvironmentConstants.REFRESH_TOKEN_COOKIE_NAME);
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(1);
        cookie.setPath("/");
        return cookie;
    }

    private String extractAccessToken(HttpServletRequest request) {
        String header = request.getHeader(ServiceConstants.AUTHORIZATION);
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }
}
