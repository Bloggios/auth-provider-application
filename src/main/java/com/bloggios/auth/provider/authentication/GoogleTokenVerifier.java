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

import com.bloggios.auth.provider.constants.ExceptionCodes;
import com.bloggios.auth.provider.exception.payloads.AuthenticationException;
import com.bloggios.auth.provider.properties.AuthServerProperties;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * Owner - Rohit Parihar and Bloggios
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.authentication
 * Created_on - June 12 - 2024
 * Created_at - 15:03
 */

@Service
@RequiredArgsConstructor
public class GoogleTokenVerifier {

    private static final Logger logger = LoggerFactory.getLogger(GoogleTokenVerifier.class);

    private final AuthServerProperties authServerProperties;

    public void authorize(String secret) {
        Map<String, AuthServerProperties.OAuthData> oAuthData = authServerProperties.getOAuth2().getOAuthData();
        AuthServerProperties.OAuthData google = oAuthData.get("google");
        String googleSecret = google.getApiSecret();
        logger.warn("Given Secret : {}", secret);
        logger.warn("Google Secret : {}", googleSecret);
        if (!googleSecret.equals(secret)) {
            throw new AuthenticationException(ExceptionCodes.GOOGLE_SECRET_VERIFICATION_FAILED);
        }
    }
}
