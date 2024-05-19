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
 * Created_on - 29 November-2023
 * Created_at - 13 : 57
 */

/**
 *
 * WT -> Write API
 * DE -> User Error or Data Error
 * IE -> Internal Server Error
 *
 */

@UtilityClass
public class ExceptionCodes {

    public static final String USER_AUTH_DOCUMENT_NULL_DAO_LAYER = "IE__AUTH-1001";
    public static final String UNABLE_TO_EXTRACT_AUTHORITIES = "IE__AUTH-1002";
    public static final String UNABLE_TO_EXTRACT_USER_ID_FROM_TOKEN = "IE__AUTH-1003";
    public static final String USER_AUTH_NULL_INTERNAL_ERROR = "IE__AUTH-1004";
    public static final String USER_NOT_FOUND = "IE__AUTH-1005";
    public static final String ROLE_NOT_FOUND_WITH_ID = "IE__AUTH-1006";
    public static final String JSON_DESERIALIZATION = "IE__AUTH-1007";
    public static final String INTERNAL_ERROR = "IE__AUTH-1008";
    public static final String USER_ID_NULL = "IE__AUTH-1009";
    public static final String FAILED_TO_FETCH_EXCEPTION_CODES = "IE__AUTH-1010";
    public static final String CHANGE_PASSWORD_REQUEST_NULL = "IE__AUTH-1011";
    public static final String USER_ID_NOT_PRESENT_TO_UPDATE_PGSQL = "IE__AUTH-1012";
    public static final String USER_ID_NOT_PRESENT_TO_UPDATE_ELASTICSEARCH = "IE__AUTH-1014";
    public static final String EMAIL_PASSED_NULL_OR_EMPTY_PGSQL = "IE__AUTH-1015";
    public static final String FORGET_PASSWORD_DOCUMENT_NULL_DAO_ES = "IE__AUTH-1017";
    public static final String EMAIL_PASSED_NULL_OR_EMPTY_FORGET_PASSWORD_ES = "IE__AUTH-1018";
    public static final String FORGET_PASSWORD_USER_ID_NOT_MATCHED_EMAIL_USER_AUTH = "IE__AUTH-1019";
    public static final String USER_ID_PASSED_NULL_OR_EMPTY_FORGET_PASSWORD_ES = "IE__AUTH-2020";
    public static final String UNABLE_TO_EXTRACT_USER_IP_FROM_TOKEN = "IE__AUTH-2021";


    public static final String USER_NOT_FOUND_WITH_EMAIL = "DE__AUTH-2001";
    public static final String REQUIRED_ROLES_NOT_PRESENT = "DE__AUTH-2002";
    public static final String INCORRECT_PASSWORD = "DE__AUTH-2003";
    public static final String USER_INACTIVE = "DE__AUTH-2004";
    public static final String ACCOUNT_EXPIRED = "DE__AUTH-2005";
    public static final String USER_CREDENTIALS_EXPIRED = "DE__AUTH-2006";
    public static final String ACCOUNT_LOCKED = "DE__AUTH-2007";
    public static final String ROLE_ALREADY_PRESENT = "DE__AUTH-2008";
    public static final String ASSIGNER_NOT_HAVE_ROLES = "DE__AUTH-2009";
    public static final String PASSWORD_EMPTY = "DE__AUTH-2010";
    public static final String EXPIRED_OTP = "DE__AUTH-2014";
    public static final String OTP_NOT_VALID = "DE__AUTH-2015";
    public static final String PASSWORD_CRITERIA_NOT_MATCHED = "DE__AUTH-2016";
    public static final String OTP_RESENT_LIMIT_EXCEED = "DE__AUTH-2017";
    public static final String EMAIL_ALREADY_PRESENT = "DE__AUTH-2018";
    public static final String EMAIL_NOT_VALID = "DE__AUTH-2019";
    public static final String USER_ALREADY_LOGGED_OUT = "DE__AUTH-2020";
    public static final String EMAIL_MANDATORY = "DE__AUTH-2021";
    public static final String NEW_PASSWORD_CANNOT_EMPTY = "DE__AUTH-2025";
    public static final String OLD_PASSWORD_CANNOT_EMPTY = "DE__AUTH-2026";
    public static final String NEW_OLD_PASSWORD_CANNOT_MATCH = "DE__AUTH-2027";
    public static final String OLD_PASSWORD_NOT_MATCHED_CURRENT_PASSWORD = "DE__AUTH-2028";
    public static final String PROVIDER_SHOULD_EMAIL_FOR_FORGET_PASSWORD = "DE__AUTH-2029";
    public static final String INVALID_UUID = "DE__AUTH-2030";
    public static final String INVALID_USER_ID = "DE__AUTH-2031";
    public static final String INVALID_FORGET_PASSWORD_OTP = "DE__AUTH-2032";
    public static final String UNAUTHORIZED_REDIRECT_URI = "DE__AUTH-2035";
    public static final String PROVIDER_NOT_EMAIL = "DE__AUTH-2040";
    public static final String LOGIN_AGAIN = "DE__AUTH-2041";
    public static final String USER_ALREADY_ENABLED = "DE__AUTH-2042";
    public static final String FP_OTP_NOT_FOUND_USER_ID = "DE__AUTH-2043";
    public static final String BAD_JWT_TOKEN = "DE__AUTH-2044";
    public static final String EXPIRED_JWT_TOKEN = "DE__AUTH-2045";
    public static final String USER_NOT_PRESENT_FOR_OTP = "DE__AUTH-2046";
    public static final String OTP_NOT_PRESENT_FOR_USER = "DE__AUTH-2048";
    public static final String ROLES_CANNOT_CONTAINS_NULL = "DE__AUTH-2049";
}
