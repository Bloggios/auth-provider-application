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

package com.bloggios.auth.provider.implementation;

import com.bloggios.auth.provider.authentication.UserPrincipal;
import com.bloggios.auth.provider.constants.BeanConstants;
import com.bloggios.auth.provider.constants.ExceptionCodes;
import com.bloggios.auth.provider.constants.ResponseMessageConstants;
import com.bloggios.auth.provider.dao.implementation.esimplementation.UserDocumentDao;
import com.bloggios.auth.provider.dao.implementation.pgsqlimplementation.UserEntityDao;
import com.bloggios.auth.provider.document.UserDocument;
import com.bloggios.auth.provider.exception.payloads.BadRequestException;
import com.bloggios.auth.provider.modal.UserEntity;
import com.bloggios.auth.provider.payload.request.AssignRoleRequest;
import com.bloggios.auth.provider.payload.request.ChangePasswordRequest;
import com.bloggios.auth.provider.payload.response.ModuleResponse;
import com.bloggios.auth.provider.payload.response.UserAuthResponse;
import com.bloggios.auth.provider.processor.elasticprocessor.EsUserAuthPersistProcessor;
import com.bloggios.auth.provider.processor.implementation.AssignRoleProcessor;
import com.bloggios.auth.provider.processor.pgsqlprocessor.PgSqlUserAuthPersist;
import com.bloggios.auth.provider.service.UserService;
import com.bloggios.auth.provider.validator.implementation.exhibitor.ChangePasswordRequestExhibitor;
import org.modelmapper.ModelMapper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.implementation
 * Created_on - 11 January-2024
 * Created_at - 21 : 11
 */

@Service
public class UserServiceImplementation implements UserService {

    private final UserDocumentDao userDocumentDao;
    private final ModelMapper modelMapper;
    private final ChangePasswordRequestExhibitor changePasswordRequestExhibitor;
    private final PasswordEncoder passwordEncoder;
    private final PgSqlUserAuthPersist pgSqlUserAuthPersist;
    private final UserEntityDao userEntityDao;
    private final AssignRoleProcessor assignRoleProcessor;
    private final EsUserAuthPersistProcessor esUserAuthPersistProcessor;

    public UserServiceImplementation(
            UserDocumentDao userDocumentDao,
            ModelMapper modelMapper,
            ChangePasswordRequestExhibitor changePasswordRequestExhibitor,
            PasswordEncoder passwordEncoder,
            PgSqlUserAuthPersist pgSqlUserAuthPersist,
            UserEntityDao userEntityDao,
            AssignRoleProcessor assignRoleProcessor,
            EsUserAuthPersistProcessor esUserAuthPersistProcessor
    ) {
        this.userDocumentDao = userDocumentDao;
        this.modelMapper = modelMapper;
        this.changePasswordRequestExhibitor = changePasswordRequestExhibitor;
        this.passwordEncoder = passwordEncoder;
        this.pgSqlUserAuthPersist = pgSqlUserAuthPersist;
        this.userEntityDao = userEntityDao;
        this.assignRoleProcessor = assignRoleProcessor;
        this.esUserAuthPersistProcessor = esUserAuthPersistProcessor;
    }

    @Override
    @Async(BeanConstants.ASYNC_TASK_EXTERNAL_POOL)
    public CompletableFuture<UserAuthResponse> getLoggedInUser(UserPrincipal userPrincipal) {
        UserDocument userAuth = userDocumentDao.findById(userPrincipal.getUserId());
        if (Objects.isNull(userAuth)) throw new BadRequestException(ExceptionCodes.USER_AUTH_NULL_INTERNAL_ERROR);
        return CompletableFuture.completedFuture(modelMapper.map(userAuth, UserAuthResponse.class));
    }

    @Override
    public CompletableFuture<ModuleResponse> changePassword(ChangePasswordRequest changePasswordRequest, UserPrincipal userPrincipal) {
        changePasswordRequestExhibitor.validate(changePasswordRequest);
        UserDocument userDocument = userDocumentDao.findById(userPrincipal.getUserId());
        if (!passwordEncoder.matches(changePasswordRequest.getOldPassword(), userDocument.getPassword())) {
            throw new BadRequestException(ExceptionCodes.OLD_PASSWORD_NOT_MATCHED_CURRENT_PASSWORD);
        }
        userDocument.setPassword(passwordEncoder.encode(changePasswordRequest.getNewPassword()));
        UserDocument savedUser = userDocumentDao.updateUser(userDocument);
        CompletableFuture.runAsync(()-> pgSqlUserAuthPersist.process(savedUser));
        return CompletableFuture.completedFuture(
                ModuleResponse
                        .builder()
                        .message(ResponseMessageConstants.PASSWORD_CHANGED)
                        .userId(userPrincipal.getUserId())
                        .build()
        );
    }

    @Override
    public CompletableFuture<ModuleResponse> assignRoles(AssignRoleRequest assignRoleRequest, UserPrincipal authenticatedUser) {
        UserEntity userAuth = userEntityDao.findById(assignRoleRequest.getAssignee())
                .orElseThrow(() -> new BadRequestException(ExceptionCodes.USER_NOT_FOUND));
        if (assignRoleRequest.getRoles().contains(null)) throw new BadRequestException(ExceptionCodes.ROLES_CANNOT_CONTAINS_NULL);
        assignRoleRequest.setUserId(authenticatedUser.getUserId());
        assignRoleRequest.setUserEntity(userAuth);
        UserEntity process = assignRoleProcessor.process(assignRoleRequest, userAuth);
        CompletableFuture.runAsync(()-> esUserAuthPersistProcessor.persistData(process));
        return CompletableFuture.completedFuture(
                ModuleResponse
                        .builder()
                        .message(ResponseMessageConstants.ROLES_ASSIGNED_SUCCESSFULLY)
                        .userId(authenticatedUser.getUserId())
                        .build()
        );
    }
}
