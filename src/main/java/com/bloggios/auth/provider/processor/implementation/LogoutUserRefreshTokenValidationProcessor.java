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

import com.bloggios.auth.provider.dao.implementation.pgsqlimplementation.RefreshTokenDao;
import com.bloggios.auth.provider.modal.RefreshTokenEntity;
import com.bloggios.auth.provider.utils.IpUtils;
import com.bloggios.auth.provider.utils.JwtDecoderUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * Owner - Rohit Parihar and Bloggios
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.processor.implementation
 * Created_on - May 16 - 2024
 * Created_at - 21:53
 */

@Component
public class LogoutUserRefreshTokenValidationProcessor {

    private static final Logger logger = LoggerFactory.getLogger(LogoutUserRefreshTokenValidationProcessor.class);

    private final RefreshTokenDao refreshTokenDao;
    private final JwtDecoder jwtDecoder;
    private final JwtDecoderUtil jwtDecoderUtil;

    public LogoutUserRefreshTokenValidationProcessor(
            RefreshTokenDao refreshTokenDao,
            JwtDecoder jwtDecoder,
            JwtDecoderUtil jwtDecoderUtil
    ) {
        this.refreshTokenDao = refreshTokenDao;
        this.jwtDecoder = jwtDecoder;
        this.jwtDecoderUtil = jwtDecoderUtil;
    }

    public void process(Optional<Cookie> optionalCookie, HttpServletRequest httpServletRequest) {
        if (optionalCookie.isEmpty()) return;
        String refreshToken = optionalCookie.get().getValue();
        try {
            jwtDecoder.decode(refreshToken);
        } catch (JwtValidationException exception) {
            Collection<OAuth2Error> errors = exception.getErrors();
            for (OAuth2Error error : errors) {
                logger.error("""
                        Refresh Token decoding error
                        {}
                        """, error);
            }
        }
        Optional<RefreshTokenEntity> refreshTokenOptional = refreshTokenDao.findByRefreshToken(refreshToken);
        if (refreshTokenOptional.isEmpty()) {
            logger.warn("""
                    Refresh Token Entity not found through Refresh Token
                    IP Address : {}
                    Date and Time : {}
                    """, IpUtils.getRemoteAddress(httpServletRequest), new Date());
            return;
        }
        String extractedUserId = jwtDecoderUtil.extractUserId(refreshToken);
        RefreshTokenEntity refreshTokenEntity = refreshTokenOptional.get();
        if (!extractedUserId.equals(refreshTokenEntity.getUserId())) {
            logger.error("""
                    User Id from Refresh Token is not matched with Entity
                    User Id from Refresh Token : {}
                    User Id from Entity : {}
                    """, extractedUserId, refreshTokenEntity.getUserId());
        }
        refreshTokenDao.deleteByEntity(refreshTokenEntity);
        logger.info("Refresh Token Entity process id completed");
    }
}
