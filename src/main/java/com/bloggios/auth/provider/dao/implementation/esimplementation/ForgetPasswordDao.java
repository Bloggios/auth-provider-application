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
import com.bloggios.auth.provider.dao.repository.elasticsearch.EsForgetPasswordRepository;
import com.bloggios.auth.provider.document.ForgetPasswordDocument;
import com.bloggios.auth.provider.exception.payloads.BadRequestException;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import java.util.Objects;
import java.util.Optional;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.dao.implementation.esimplementation
 * Created_on - 15 January-2024
 * Created_at - 16 : 43
 */

@Component
public class ForgetPasswordDao extends EsAbstractDao<ForgetPasswordDocument, EsForgetPasswordRepository> {

    protected ForgetPasswordDao(EsForgetPasswordRepository repository) {
        super(repository);
    }

    @Override
    protected ForgetPasswordDocument initCreate(ForgetPasswordDocument forgetPasswordDocument) {
        if (Objects.isNull(forgetPasswordDocument)) throw new BadRequestException(ExceptionCodes.FORGET_PASSWORD_DOCUMENT_NULL_DAO_ES);
        return super.initCreate(forgetPasswordDocument);
    }

    public Optional<ForgetPasswordDocument> findByEmail(String email) {
        if (Objects.isNull(email) || ObjectUtils.isEmpty(email)) {
            throw new BadRequestException(ExceptionCodes.EMAIL_PASSED_NULL_OR_EMPTY_FORGET_PASSWORD_ES);
        }
        return repository.findByEmail(email);
    }

    public void delete(ForgetPasswordDocument forgetPasswordDocument) {
        if (Objects.isNull(forgetPasswordDocument)) throw new BadRequestException(ExceptionCodes.FORGET_PASSWORD_DOCUMENT_NULL_DAO_ES);
        repository.delete(forgetPasswordDocument);
    }

    public ForgetPasswordDocument findByUserId(String userId) {
        if (Objects.isNull(userId) || ObjectUtils.isEmpty(userId)) {
            throw new BadRequestException(ExceptionCodes.USER_ID_PASSED_NULL_OR_EMPTY_FORGET_PASSWORD_ES);
        }
        return repository.findByUserId(userId).orElseThrow(()-> new BadRequestException(ExceptionCodes.FP_OTP_NOT_FOUND_USER_ID));
    }
}
