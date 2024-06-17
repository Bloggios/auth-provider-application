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

package com.bloggios.auth.provider.dao.implementation.esimplementation;

import com.bloggios.auth.provider.constants.ExceptionCodes;
import com.bloggios.auth.provider.dao.EsAbstractDao;
import com.bloggios.auth.provider.dao.repository.elasticsearch.UserDocumentRepository;
import com.bloggios.auth.provider.document.UserDocument;
import com.bloggios.auth.provider.exception.payloads.BadRequestException;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import java.util.Date;
import java.util.Objects;
import java.util.Optional;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.dao.implementation.esimplementation
 * Created_on - 11 January-2024
 * Created_at - 20 : 01
 */

@Component
public class UserDocumentDao extends EsAbstractDao<UserDocument, UserDocumentRepository> {

    protected UserDocumentDao(UserDocumentRepository repository) {
        super(repository);
    }

    public UserDocument createUser(UserDocument userDocument) {
        if (Objects.isNull(userDocument))
            throw new BadRequestException(ExceptionCodes.USER_AUTH_DOCUMENT_NULL_DAO_LAYER);
        if (userDocument.getUserId() == null) {
            throw new BadRequestException(ExceptionCodes.USER_ID_NULL);
        }
        return repository.save(userDocument);
    }

    public UserDocument findById(String userId) {
        return repository.findById(userId)
                .orElseThrow(() -> new BadRequestException(ExceptionCodes.USER_NOT_FOUND));
    }

    public UserDocument updateUser(UserDocument userDocument) {
        if (Objects.isNull(userDocument))
            throw new BadRequestException(ExceptionCodes.USER_AUTH_DOCUMENT_NULL_DAO_LAYER);
        if (Objects.isNull(userDocument.getUserId()) || ObjectUtils.isEmpty(userDocument.getUserId())) {
            throw new BadRequestException(ExceptionCodes.USER_ID_NOT_PRESENT_TO_UPDATE_ELASTICSEARCH);
        }
        userDocument.setLastUpdated(new Date());
        return repository.save(userDocument);
    }

    public Optional<UserDocument> findByEmailOrUsername(String data) {
        return repository.findByEmailOrUsername(data, data);
    }

    public Optional<UserDocument> findByUsername(String username) {
        return repository.findByUsername(username);
    }
}
