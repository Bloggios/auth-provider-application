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

import com.bloggios.auth.provider.authentication.UserPrincipal;
import com.bloggios.auth.provider.constants.ExceptionCodes;
import com.bloggios.auth.provider.exception.payloads.AuthenticationException;
import com.bloggios.auth.provider.properties.AuthServerProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.bloggios.auth.provider.constants.ServiceConstants.ORIGIN;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.processor.implementation
 * Created_on - 13 December-2023
 * Created_at - 16 : 12
 */

@Component
public class LoginDataProcessor {

    private static final Logger logger = LoggerFactory.getLogger(LoginDataProcessor.class);

    private final AuthServerProperties authenticationProperties;

    public LoginDataProcessor(
            AuthServerProperties authenticationProperties
    ) {
        this.authenticationProperties = authenticationProperties;
    }

    public void validateOrigins(Authentication authentication, HttpServletRequest httpServletRequest) {
        String origin = httpServletRequest.getHeader(ORIGIN);
        UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();
        Collection<? extends GrantedAuthority> authorities = principal.getAuthorities();
        if (ObjectUtils.isEmpty(origin)) {
            validateForNullOrigin(authorities);
        } else {
            validateForEnvironment(origin, authorities);
        }
    }

    private void validateForNullOrigin(Collection<? extends GrantedAuthority> authorities) {
        boolean isPresent;
        AuthServerProperties.RoleToAllow roleToAllow = authenticationProperties.getAllowedRoles().getRolesToAllow().get("api-testing");
        isPresent = checkAllRolesContain(authorities, roleToAllow.getMustRoles());
        if (!isPresent) {
            logger.error(ExceptionCodes.REQUIRED_ROLES_NOT_PRESENT);
            throw new AuthenticationException(ExceptionCodes.REQUIRED_ROLES_NOT_PRESENT);
        }
    }

    private void validateForEnvironment(String origin, Collection<? extends GrantedAuthority> authorities) {
        boolean isPresent = false;
        Map<String, AuthServerProperties.RoleToAllow> roleToAllow = authenticationProperties.getAllowedRoles().getRolesToAllow();
        for (String origins : roleToAllow.keySet()) {
            AuthServerProperties.RoleToAllow requiredRoles = roleToAllow.get(origins);
            if (requiredRoles.getOriginName().equals(origin)) {
                isPresent = checkAllRolesContain(authorities, requiredRoles.getMustRoles());
                break;
            }
        }
        if (!isPresent) {
            logger.error(ExceptionCodes.REQUIRED_ROLES_NOT_PRESENT);
            throw new AuthenticationException(ExceptionCodes.REQUIRED_ROLES_NOT_PRESENT);
        }
    }

    private boolean checkAllRolesContain(Collection<? extends GrantedAuthority> authorities, List<String> rolesToCheck) {
        List<String> userRoles = authorities
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        Map<String, Integer> frequencyMap = new HashMap<>();
        for (String element : userRoles) {
            frequencyMap.put(element, frequencyMap.getOrDefault(element, 0) + 1);
        }
        for (String element : rolesToCheck) {
            if (frequencyMap.containsKey(element) && frequencyMap.get(element) > 0) {
                frequencyMap.put(element, frequencyMap.get(element) - 1);
            } else {
                return false;
            }
        }
        return true;
    }
}
