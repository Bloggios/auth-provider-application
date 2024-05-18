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

package com.bloggios.auth.provider.constants;

import lombok.experimental.UtilityClass;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.constants
 * Created_on - 11 January-2024
 * Created_at - 20 : 34
 */

@UtilityClass
public class EndpointConstants {
    public static final String CONTEXT_PATH = "/auth-provider";

    public static final String AUTHENTICATION_BASE_PATH = CONTEXT_PATH + "/authentication";
    public static final String USER_READ_BASE_PATH = CONTEXT_PATH + "/user-auth/read";
    public static final String LIST = "/list";
    public static final String CHANGE_PASSWORD = "/change-password";

    public static class AuthenticationController {
        public static final String BASE_PATH = CONTEXT_PATH + "/auth";
        public static final String LOGIN_PATH = "/token";
        public static final String REGISTER_PATH = "/register";
        public static final String FORGET_PASSWORD_OTP_PATH = "/forget-password-otp";
        public static final String FORGET_PASSWORD_PATH = "/forget-password";
        public static final String REMOTE_ADDRESS = "/remote-address";
        public static final String VERIFY_OTP = "/verify-otp";
        public static final String RESEND_OTP = "/resend-otp";
        public static final String REFRESH_TOKEN = "/refresh-token";
        public static final String OTP_USER_ID = "/otp-userId";
        public static final String LOGOUT = "/logout";
        public static final String USER_IP = "/user-ip";
        public static final String REFRESH_TOKEN_SOCIAL = "/refresh-token-social";
    }

    public static class UserController {
        public static final String BASE_PATH = CONTEXT_PATH + "/user";
        public static final String CHANGE_PASSWORD = "/change-password";
        public static final String ASSIGN_ROLES = "/assign-roles";
    }
}
