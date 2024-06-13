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

package com.bloggios.auth.provider.controller;

import com.bloggios.auth.provider.constants.EndpointConstants;
import com.bloggios.auth.provider.constants.ServiceConstants;
import com.bloggios.auth.provider.implementation.AuthenticationServiceImplementation;
import com.bloggios.auth.provider.payload.response.AuthResponse;
import com.bloggios.auth.provider.utils.AsyncUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.util.concurrent.CompletableFuture;

/**
 * Owner - Rohit Parihar and Bloggios
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.controller
 * Created_on - June 13 - 2024
 * Created_at - 00:12
 */

@RestController
@RequestMapping(EndpointConstants.OAuthController.BASE_PATH)
@Slf4j
public class OAuthController {

    private final AuthenticationServiceImplementation authenticationServiceImplementation;

    public OAuthController(AuthenticationServiceImplementation authenticationServiceImplementation) {
        this.authenticationServiceImplementation = authenticationServiceImplementation;
    }

    @GetMapping(EndpointConstants.OAuthController.GOOGLE_LOGIN)
    public ResponseEntity<AuthResponse> loginGoogle(@RequestParam String token, @RequestParam String secret, HttpServletRequest httpServletRequest) {
        log.error("4004 : {}", httpServletRequest.getHeader(ServiceConstants.ORIGIN));
        CompletableFuture<AuthResponse> authenticate = authenticationServiceImplementation.loginGoogle(token, secret, httpServletRequest);
        AuthResponse asyncResult = AsyncUtils.getAsyncResult(authenticate);
        return ResponseEntity
                .ok()
                .header(HttpHeaders.SET_COOKIE, asyncResult.getCookie().toString())
                .header(ServiceConstants.COOKIE_TOKEN, asyncResult.getCookieToken())
                .body(asyncResult);
    }
}
