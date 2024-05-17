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

import com.bloggios.auth.provider.dao.implementation.pgsqlimplementation.UserEntityDao;
import com.bloggios.auth.provider.document.UserDocument;
import com.bloggios.auth.provider.enums.DaoStatus;
import com.bloggios.auth.provider.modal.UserEntity;
import com.bloggios.auth.provider.processor.Process;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import java.util.Objects;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.processor.implementation
 * Created_on - 14 January-2024
 * Created_at - 18 : 18
 */

@Component
public class PgSqlUserAuthPersistProcessor implements Process<UserDocument> {

    private final UserEntityDao userEntityDao;
    private final ModelMapper modelMapper;

    public PgSqlUserAuthPersistProcessor(
            UserEntityDao userEntityDao,
            ModelMapper modelMapper
    ) {
        this.userEntityDao = userEntityDao;
        this.modelMapper = modelMapper;
    }

    @Override
    public void process(UserDocument userDocument) {
        UserEntity userEntity = modelMapper.map(userDocument, UserEntity.class);
        if (Objects.nonNull(userEntity) && !ObjectUtils.isEmpty(userEntity.getUserId())) {
            userEntityDao.initOperation(DaoStatus.UPDATE, userEntity);
        }
    }
}
