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
import com.bloggios.auth.provider.dao.repository.postgres.PgSqlRoleRepository;
import com.bloggios.auth.provider.exception.payloads.BadRequestException;
import com.bloggios.auth.provider.modal.RoleEntity;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.dao.implementation
 * Created_on - 30 November-2023
 * Created_at - 00 : 39
 */

@Component
public class RoleDao extends AbstractDao<RoleEntity, PgSqlRoleRepository> {

    protected RoleDao(PgSqlRoleRepository repository) {
        super(repository);
    }

    public List<RoleEntity> findAllRoles() {
        return repository.findAll();
    }

    public long countRecords() {
        return repository.count();
    }

    public List<RoleEntity> batchSave(List<RoleEntity> roles) {
        return repository.saveAll(roles);
    }

    public List<RoleEntity> findAll() {
        return repository.findAll();
    }

    public RoleEntity findById(String roleId) {
        return repository.findById(roleId)
                .orElseThrow(()-> new BadRequestException(ExceptionCodes.ROLE_NOT_FOUND_WITH_ID));
    }
}
