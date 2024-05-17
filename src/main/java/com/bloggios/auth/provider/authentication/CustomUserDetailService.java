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
import com.bloggios.auth.provider.dao.implementation.esimplementation.UserDocumentDao;
import com.bloggios.auth.provider.document.UserDocument;
import com.bloggios.auth.provider.exception.payloads.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.authentication
 * Created_on - 10 December-2023
 * Created_at - 17 : 14
 */

@Service
public class CustomUserDetailService implements UserDetailsService {

    private final UserDocumentDao userDocumentDao;

    public CustomUserDetailService(
            UserDocumentDao userDocumentDao
    ) {
        this.userDocumentDao = userDocumentDao;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserDocument> byEmail = userDocumentDao.findByEmailOrUsername(username);
        if (byEmail.isEmpty()) throw new AuthenticationException(ExceptionCodes.USER_NOT_FOUND);
        return UserPrincipal.create(byEmail.get());
    }

    @Transactional
    public UserDetails loadUserById(String id) {
        UserDocument auth = userDocumentDao.findById(id);
        return UserPrincipal.create(auth);
    }
}
