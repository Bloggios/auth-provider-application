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

    public static final String FILTER_KEY_NOT_PRESENT = "BG-AUTH-ESLS-5001";
    public static final String FILTER_KEY_TYPE_MANDATORY = "BG-AUTH-ESLS-5002";
    public static final String INVALID_SELECTION_DATATYPE_BOOLEAN = "BG-AUTH-ESLS-5003";
    public static final String INVALID_SELECTION_DATATYPE_DATETIME = "BG-AUTH-ESLS-5004";
    public static final String INVALID_SELECTION_DATATYPE_DOUBLE = "BG-AUTH-ESLS-5005";
    public static final String INVALID_SELECTION_DATATYPE_INTEGER = "BG-AUTH-ESLS-5006";
    public static final String INVALID_SELECTION_DATATYPE_LONG = "BG-AUTH-ESLS-5007";
    public static final String BOTH_PAGE_SIZE_MANDATORY = "BG-AUTH-ESLS-5008";
    public static final String PAGE_SIZE_LIMIT_EXCEED = "BG-AUTH-ESLS-5009";
    public static final String PAGE_LESS_THAN_ZERO = "BG-AUTH-ESLS-5010";
    public static final String MIN_RANGE_DATE_TIME_NOT_VALID = "BG-AUTH-ESLS-5011";
    public static final String MAX_RANGE_DATE_TIME_NOT_VALID = "BG-AUTH-ESLS-5012";
    public static final String MIN_RANGE_INVALID_DOUBLE_TYPE = "BG-AUTH-ESLS-5014";
    public static final String MAX_RANGE_INVALID_DOUBLE_TYPE = "BG-AUTH-ESLS-5015";
    public static final String MIN_RANGE_INVALID_INTEGER_TYPE = "BG-AUTH-ESLS-5016";
    public static final String MAX_RANGE_INVALID_INTEGER_TYPE = "BG-AUTH-ESLS-5017";
    public static final String RANGE_FILTER_KEY_NOT_PRESENT = "BG-AUTH-ESLS-5018";
    public static final String RANGE_FILTER_KEY_TYPE_NOT_PRESENT = "BG-AUTH-ESLS-5019";
    public static final String MIN_MAX_MANDATORY_RANGE_FILTER = "BG-AUTH-ESLS-5020";
    public static final String INVALID_SELECTION_FOR_OPERATOR = "BG-AUTH-ESLS-5021";
    public static final String MAX_SHOULD_EMPTY_FOR_NE_OPERATOR = "BG-AUTH-ESLS-5022";
    public static final String SEARCH_FILTER_WITH_EMPTY_FIELD = "BG-AUTH-ESLS-5023";
    public static final String FIELD_NOT_PRESENT_FOR_SEARCHING_NGRAM = "BG-AUTH-ESLS-5024";
    public static final String NGRAM_SEARCH_TEXT_EMPTY = "BG-AUTH-ESLS-5025";
    public static final String SEARCH_TEXT_EMPTY = "BG-AUTH-ESLS-5026";
    public static final String SIZE_NOT_GREATER_THAN_ZERO = "BG-AUTH-ESLS-5027";
    public static final String SORT_KEY_NOT_PRESENT = "BG-AUTH-ESLS-5028";
    public static final String SORT_ORDER_NOT_PRESENT = "BG-AUTH-ESLS-5029";

    public static final String USER_ID_NOT_PRESENT_VERIFY_OTP = "BG-AUTH-FE-4001";
    public static final String USER_ALREADY_ENABLED = "BG-AUTH-FE-4002";
    public static final String INVALID_RANGE_FILTER_OPERATOR = "BG-AUTH-FE-4003";
    public static final String BAD_JWT_TOKEN = "BG-AUTH-FE-4004";
    public static final String EXPIRED_JWT_TOKEN = "BG-AUTH-FE-4005";
    public static final String USER_NOT_PRESENT_FOR_OTP = "BG-AUTH-FE-4006";
    public static final String LOGOUT_AND_LOGIN_AGAIN = "BG-AUTH-FE-4007";
    public static final String OTP_NOT_PRESENT_FOR_USER = "BG-AUTH-FE-4008";
    public static final String ROLES_CANNOT_CONTAINS_NULL = "BG-AUTH-FE-4009";
    public static final String PROVIDER_NOT_EMAIL = "BG-AUTH-FE-4010";
    public static final String LOGIN_AGAIN = "BG-AUTH-FE-4011";
    public static final String LIST_REQUEST_IS_EMPTY = "BG-AUTH-FE-4012";
    public static final String FP_OTP_NOT_FOUND_USER_ID = "BG-AUTH-FE-4014";


    public static final String USER_AUTH_DOCUMENT_NULL_DAO_LAYER = "BG-AUTH-IE-1001";
    public static final String UNABLE_TO_EXTRACT_AUTHORITIES = "BG-AUTH-IE-1002";
    public static final String UNABLE_TO_EXTRACT_USER_ID_FROM_TOKEN = "BG-AUTH-IE-1003";
    public static final String USER_AUTH_NULL_INTERNAL_ERROR = "BG-AUTH-IE-1004";
    public static final String USER_NOT_FOUND = "BG-AUTH-IE-1005";
    public static final String ROLE_NOT_FOUND_WITH_ID = "BG-AUTH-IE-1006";
    public static final String JSON_DESERIALIZATION = "BG-AUTH-IE-1007";
    public static final String INTERNAL_ERROR = "BG-AUTH-IE-1008";
    public static final String USER_ID_NULL = "BG-AUTH-IE-1009";
    public static final String FAILED_TO_FETCH_EXCEPTION_CODES = "BG-AUTH-IE-1010";
    public static final String CHANGE_PASSWORD_REQUEST_NULL = "BG-AUTH-IE-1011";
    public static final String USER_ID_NOT_PRESENT_TO_UPDATE_PGSQL = "BG-AUTH-IE-1012";
    public static final String USER_ID_NOT_PRESENT_TO_UPDATE_ELASTICSEARCH = "BG-AUTH-IE-1014";
    public static final String EMAIL_PASSED_NULL_OR_EMPTY_PGSQL = "BG-AUTH-IE-1015";
    public static final String FORGET_PASSWORD_DOCUMENT_NULL_DAO_ES = "BG-AUTH-IE-1017";
    public static final String EMAIL_PASSED_NULL_OR_EMPTY_FORGET_PASSWORD_ES = "BG-AUTH-IE-1018";
    public static final String FORGET_PASSWORD_USER_ID_NOT_MATCHED_EMAIL_USER_AUTH = "BG-AUTH-IE-1019";
    public static final String USER_ID_PASSED_NULL_OR_EMPTY_FORGET_PASSWORD_ES = "BG-AUTH-IE-2020";
    public static final String UNABLE_TO_EXTRACT_USER_IP_FROM_TOKEN = "BG-AUTH-IE-2021";


    public static final String USER_NOT_FOUND_WITH_EMAIL = "BG-AUTH-DE-2001";
    public static final String REQUIRED_ROLES_NOT_PRESENT = "BG-AUTH-DE-2002";
    public static final String INCORRECT_PASSWORD = "BG-AUTH-DE-2003";
    public static final String USER_INACTIVE = "BG-AUTH-DE-2004";
    public static final String ACCOUNT_EXPIRED = "BG-AUTH-DE-2005";
    public static final String USER_CREDENTIALS_EXPIRED = "BG-AUTH-DE-2006";
    public static final String ACCOUNT_LOCKED = "BG-AUTH-DE-2007";
    public static final String ROLE_ALREADY_PRESENT = "BG-AUTH-DE-2008";
    public static final String ASSIGNER_NOT_HAVE_ROLES = "BG-AUTH-DE-2009";
    public static final String PASSWORD_EMPTY = "BG-AUTH-DE-2010";
    public static final String OTP_EMPTY = "BG-AUTH-DE-2011";
    public static final String EXPIRED_OTP = "BG-AUTH-DE-2014";
    public static final String OTP_NOT_VALID = "BG-AUTH-DE-2015";
    public static final String PASSWORD_CRITERIA_NOT_MATCHED = "BG-AUTH-DE-2016";
    public static final String OTP_RESENT_LIMIT_EXCEED = "BG-AUTH-DE-2017";
    public static final String EMAIL_ALREADY_PRESENT = "BG-AUTH-DE-2018";
    public static final String EMAIL_NOT_VALID = "BG-AUTH-DE-2019";
    public static final String USER_ALREADY_LOGGED_OUT = "BG-AUTH-DE-2020";
    public static final String EMAIL_MANDATORY = "BG-AUTH-DE-2021";
    public static final String FILTER_KEY_NOT_VALID = "BG-AUTH-DE-2022";
    public static final String RANGE_FILTER_KEY_NOT_VALID = "BG-AUTH-DE-2023";
    public static final String SORT_KEY_NOT_VALID = "BG-AUTH-DE-2024";
    public static final String NEW_PASSWORD_CANNOT_EMPTY = "BG-AUTH-DE-2025";
    public static final String OLD_PASSWORD_CANNOT_EMPTY = "BG-AUTH-DE-2026";
    public static final String NEW_OLD_PASSWORD_CANNOT_MATCH = "BG-AUTH-DE-2027";
    public static final String OLD_PASSWORD_NOT_MATCHED_CURRENT_PASSWORD = "BG-AUTH-DE-2028";
    public static final String PROVIDER_SHOULD_EMAIL_FOR_FORGET_PASSWORD = "BG-AUTH-DE-2029";
    public static final String INVALID_UUID = "BG-AUTH-DE-2030";
    public static final String INVALID_USER_ID = "BG-AUTH-DE-2031";
    public static final String INVALID_FORGET_PASSWORD_OTP = "BG-AUTH-DE-2032";
    public static final String IP_NOT_MATCHED_REFRESH_TOKEN = "BG-AUTH-DE-2034";
    public static final String UNAUTHORIZED_REDIRECT_URI = "BG-AUTH-DE-2035";
    public static final String ACCESS_DENIED = "BG-AUTH-DE-2036";
}
