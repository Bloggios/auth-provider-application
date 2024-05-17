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

package com.bloggios.auth.provider.dao.implementation.pgsqlimplementation;

import com.bloggios.auth.provider.constants.ExceptionCodes;
import com.bloggios.auth.provider.dao.AbstractDao;
import com.bloggios.auth.provider.dao.repository.postgres.PgSqlUserAuthRepository;
import com.bloggios.auth.provider.exception.payloads.BadRequestException;
import com.bloggios.auth.provider.modal.UserEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import java.util.Date;
import java.util.Objects;
import java.util.Optional;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.dao.implementation
 * Created_on - 29 November-2023
 * Created_at - 23 : 53
 */

@Component
public class UserEntityDao extends AbstractDao<UserEntity, PgSqlUserAuthRepository> {

    public UserEntityDao(PgSqlUserAuthRepository repository) {
        super(repository);
    }

    public boolean existsByEmail(String email) {
        String dataToCheck = email.trim().toLowerCase();
        return repository.existsByEmail(dataToCheck);
    }

    public Optional<UserEntity> findById(String userId) {
        if (ObjectUtils.isEmpty(userId)) throw new BadRequestException(ExceptionCodes.USER_ID_NULL);
        return repository.findById(userId);
    }

    public UserEntity findUserById(String userId) {
        if (ObjectUtils.isEmpty(userId)) throw new BadRequestException(ExceptionCodes.USER_ID_NULL);
        return repository.findById(userId).orElseThrow(()-> new BadRequestException(ExceptionCodes.USER_NOT_FOUND));
    }

    @Override
    protected UserEntity initUpdate(UserEntity userEntity) {
        if (Objects.isNull(userEntity.getUserId()) || ObjectUtils.isEmpty(userEntity.getUserId())) {
            throw new BadRequestException(ExceptionCodes.USER_ID_NOT_PRESENT_TO_UPDATE_PGSQL);
        }
        if (Objects.isNull(userEntity.getUserId()) || ObjectUtils.isEmpty(userEntity.getUserId())) {
            throw new BadRequestException(ExceptionCodes.USER_ID_NOT_PRESENT_TO_UPDATE_PGSQL);
        }
        userEntity.setLastUpdated(new Date());
        return super.initUpdate(userEntity);
    }

    public UserEntity findByEmail(String email) {
        if (Objects.isNull(email) || ObjectUtils.isEmpty(email)) {
            throw new BadRequestException(ExceptionCodes.EMAIL_PASSED_NULL_OR_EMPTY_PGSQL);
        }
        Optional<UserEntity> byEmail = repository.findByEmail(email);
        if (byEmail.isEmpty()) {
            throw new BadRequestException(ExceptionCodes.USER_NOT_FOUND_WITH_EMAIL);
        }
        return byEmail.get();
    }

    public Optional<UserEntity> findByEmailOptional(String email) {
        if (Objects.isNull(email) || ObjectUtils.isEmpty(email)) {
            throw new BadRequestException(ExceptionCodes.EMAIL_PASSED_NULL_OR_EMPTY_PGSQL);
        }
        return repository.findByEmail(email);
    }
}
