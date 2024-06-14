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
import com.bloggios.auth.provider.payload.record.RemoteAddressResponse;
import com.bloggios.auth.provider.payload.request.AuthenticationRequest;
import com.bloggios.auth.provider.payload.request.ForgetPasswordRequest;
import com.bloggios.auth.provider.payload.request.GoogleLoginRequest;
import com.bloggios.auth.provider.payload.request.RegisterRequest;
import com.bloggios.auth.provider.payload.response.AuthResponse;
import com.bloggios.auth.provider.payload.response.ModuleResponse;
import com.bloggios.auth.provider.service.AuthenticationService;
import com.bloggios.auth.provider.utils.AsyncUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.concurrent.CompletableFuture;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.controller
 * Created_on - 11 January-2024
 * Created_at - 20 : 34
 */

@RestController
@RequestMapping(EndpointConstants.AuthenticationController.BASE_PATH)
@Slf4j
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    public AuthenticationController(
            AuthenticationService authenticationService
    ) {
        this.authenticationService = authenticationService;
    }

    @PostMapping(EndpointConstants.AuthenticationController.REGISTER_PATH)
    public ResponseEntity<ModuleResponse> registerUser(@RequestBody RegisterRequest registerRequest, HttpServletRequest request) {
        return ResponseEntity.ok(AsyncUtils.getAsyncResult(authenticationService.registerUser(registerRequest, request)));
    }

    @PostMapping(EndpointConstants.AuthenticationController.LOGIN_PATH)
    public ResponseEntity<AuthResponse> authenticate(@RequestBody AuthenticationRequest authenticationRequest, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        CompletableFuture<AuthResponse> authenticate = authenticationService.authenticate(authenticationRequest, httpServletRequest, httpServletResponse);
        AuthResponse asyncResult = AsyncUtils.getAsyncResult(authenticate);
        return ResponseEntity
                .ok()
                .header(HttpHeaders.SET_COOKIE, asyncResult.getCookie().toString())
                .header(ServiceConstants.COOKIE_TOKEN, asyncResult.getCookieToken())
                .body(asyncResult);
    }

    @GetMapping(EndpointConstants.AuthenticationController.VERIFY_OTP)
    public ResponseEntity<ModuleResponse> verifyOtp(@RequestHeader("otp") String otp, @RequestParam("userId") String userId) {
        return ResponseEntity.ok(AsyncUtils.getAsyncResult(authenticationService.verifyOtp(otp, userId)));
    }

    @GetMapping(EndpointConstants.AuthenticationController.RESEND_OTP)
    public ResponseEntity<ModuleResponse> resendOtp(@RequestParam(value = "userId") String userId) {
        return ResponseEntity.ok(AsyncUtils.getAsyncResult(authenticationService.resendOtp(userId)));
    }

    @GetMapping(EndpointConstants.AuthenticationController.REFRESH_TOKEN)
    public ResponseEntity<AuthResponse> refreshToken(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        AuthResponse response = AsyncUtils.getAsyncResult(authenticationService.refreshToken(httpServletRequest, httpServletResponse));
        return ResponseEntity
                .ok()
                .header(HttpHeaders.SET_COOKIE, response.getCookie().toString())
                .header(ServiceConstants.COOKIE_TOKEN, response.getCookieToken())
                .body(response);
    }

    @PostMapping(EndpointConstants.AuthenticationController.OTP_USER_ID)
    public ResponseEntity<ModuleResponse> otpRedirectUserId(@RequestBody AuthenticationRequest authenticationRequest) {
        return ResponseEntity.ok(AsyncUtils.getAsyncResult(authenticationService.otpRedirectUserId(authenticationRequest)));
    }

    @GetMapping(EndpointConstants.AuthenticationController.LOGOUT)
    public ResponseEntity<AuthResponse> logoutUser(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        AuthResponse authResponse = AsyncUtils.getAsyncResult(authenticationService.logoutUser(httpServletRequest, httpServletResponse));
        return ResponseEntity
                .ok()
                .header(HttpHeaders.SET_COOKIE, authResponse.getCookie().toString())
                .body(authResponse);
    }

    @GetMapping(EndpointConstants.AuthenticationController.USER_IP)
    public ResponseEntity<String> userIp(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        String clientIp = httpServletRequest.getHeader("X-Forwarded-For");
        if (clientIp != null && clientIp.contains(",")) {
            clientIp = clientIp.split(",")[0].trim();
        }
        return ResponseEntity.ok(clientIp);
    }

    @GetMapping(EndpointConstants.AuthenticationController.REFRESH_TOKEN_SOCIAL)
    public ResponseEntity<AuthResponse> refreshTokenSocial(@RequestParam String token, HttpServletResponse httpServletResponse, HttpServletRequest httpServletRequest) {
        AuthResponse response = AsyncUtils.getAsyncResult(authenticationService.refreshTokenSocial(token, httpServletResponse, httpServletRequest));
        return ResponseEntity
                .ok()
                .header(HttpHeaders.SET_COOKIE, response.getCookie().toString())
                .header(ServiceConstants.COOKIE_TOKEN, response.getCookieToken())
                .body(response);
    }

    @GetMapping(EndpointConstants.AuthenticationController.FORGET_PASSWORD_OTP_PATH)
    public ResponseEntity<ModuleResponse> forgetPasswordOtp(@RequestParam(name = "email") String email) {
        return ResponseEntity.ok(AsyncUtils.getAsyncResult(authenticationService.forgetPasswordOtp(email)));
    }

    @PostMapping(EndpointConstants.AuthenticationController.FORGET_PASSWORD_PATH)
    public ResponseEntity<ModuleResponse> forgetPassword(@RequestBody ForgetPasswordRequest forgetPasswordRequest) {
        return ResponseEntity.ok(AsyncUtils.getAsyncResult(authenticationService.forgetPassword(forgetPasswordRequest)));
    }

    @GetMapping(EndpointConstants.AuthenticationController.REMOTE_ADDRESS)
    public ResponseEntity<RemoteAddressResponse> remoteAddress(HttpServletRequest request) {
        return ResponseEntity.ok(AsyncUtils.getAsyncResult(authenticationService.remoteAddress(request)));
    }

    @PostMapping(EndpointConstants.OAuthController.GOOGLE_LOGIN)
    public ResponseEntity<AuthResponse> loginGoogle(@RequestBody GoogleLoginRequest googleLoginRequest, HttpServletRequest httpServletRequest) {
        CompletableFuture<AuthResponse> authenticate = authenticationService.loginGoogle(googleLoginRequest, httpServletRequest);
        AuthResponse asyncResult = AsyncUtils.getAsyncResult(authenticate);
        return ResponseEntity
                .ok()
                .header(HttpHeaders.SET_COOKIE, asyncResult.getCookie().toString())
                .header(ServiceConstants.COOKIE_TOKEN, asyncResult.getCookieToken())
                .body(asyncResult);
    }
}
