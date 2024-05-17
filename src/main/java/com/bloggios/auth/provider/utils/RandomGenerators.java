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

package com.bloggios.auth.provider.utils;

import lombok.experimental.UtilityClass;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.utils
 * Created_on - 07 December-2023
 * Created_at - 16 : 15
 */

@UtilityClass
public class RandomGenerators {

    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("MMdduuuuHHmmss");
    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String NUMBERS = "0123456789";
    private static final int ALPHABET_LENGTH = ALPHABET.length();
    private static final int NUMBERS_LENGTH = NUMBERS.length();

    public static String generateClientId(String userId) {
        String dateTimePart = getCurrentDateAndTime();
        String randomPart = generateRandomString(20);
        String userIdPart = userId.split("-")[0];
        String staticPart = "auth.bloggios.com";
        return dateTimePart + "-" + randomPart + "-" + userIdPart + "." + staticPart;
    }

    public static String generateClientSecret() {
        String prefix = "BLOGGIOS";
        String randomPart = generateRandomString(16);
        return prefix + "-" + randomPart;
    }

    public static String generateProjectId(String projectName) {
        String randomPart = generateRandomString(5);
        String projectNamePart = projectName.split(" ")[0];
        String staticPart = "BG";
        return staticPart + "-" + randomPart + "-" + projectNamePart;
    }

    private static String generateRandomString(int length) {
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder randomStringBuilder = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            boolean isDigit = secureRandom.nextBoolean();

            if (isDigit) {
                int randomIndex = secureRandom.nextInt(NUMBERS_LENGTH);
                randomStringBuilder.append(NUMBERS.charAt(randomIndex));
            } else {
                int randomIndex = secureRandom.nextInt(ALPHABET_LENGTH);
                randomStringBuilder.append(ALPHABET.charAt(randomIndex));
            }
        }

        return randomStringBuilder.toString();
    }

    private static String getCurrentDateAndTime() {
        return LocalDateTime.now().format(DATE_TIME_FORMATTER);
    }
}
