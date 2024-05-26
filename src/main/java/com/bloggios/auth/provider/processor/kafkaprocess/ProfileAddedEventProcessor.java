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

package com.bloggios.auth.provider.processor.kafkaprocess;

import com.bloggios.auth.provider.constants.BeanConstants;
import com.bloggios.auth.provider.constants.ServiceConstants;
import com.bloggios.auth.provider.dao.implementation.pgsqlimplementation.UserEntityDao;
import com.bloggios.auth.provider.enums.DaoStatus;
import com.bloggios.auth.provider.modal.RoleEntity;
import com.bloggios.auth.provider.modal.UserEntity;
import com.bloggios.auth.provider.payload.event.ProfileAddedEvent;
import com.bloggios.auth.provider.processor.KafkaProcess;
import com.bloggios.auth.provider.processor.elasticprocessor.EsUserAuthUpdateProcessor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.processor.kafkaprocess
 * Created_on - 17 March-2024
 * Created_at - 21 : 09
 */

@Component(BeanConstants.PROFILE_ADDED_EVENT_LISTENER)
@Slf4j
public class ProfileAddedEventProcessor implements KafkaProcess<ProfileAddedEvent> {

    private final UserEntityDao userEntityDao;
    private final EsUserAuthUpdateProcessor esUserAuthUpdateProcessor;

    public ProfileAddedEventProcessor(
            UserEntityDao userEntityDao,
            EsUserAuthUpdateProcessor esUserAuthUpdateProcessor
    ) {
        this.userEntityDao = userEntityDao;
        this.esUserAuthUpdateProcessor = esUserAuthUpdateProcessor;
    }

    @Override
    @Transactional
    public void process(ProfileAddedEvent profileAddedEvent) {
        if (profileAddedEvent != null) {
            UserEntity userEntity = userEntityDao.findUserById(profileAddedEvent.getUserId());
            List<RoleEntity> roles = userEntity.getRoles();
            Optional<RoleEntity> optionalDummy = roles
                    .stream()
                    .filter(role -> role.getRoleId().equals(ServiceConstants.DUMMY_ROLE))
                    .findFirst();
            optionalDummy.ifPresent(roles::remove);
            userEntity.setRoles(roles);
            userEntity.setProfileAdded(true);
            UserEntity response = userEntityDao.initOperation(DaoStatus.UPDATE, userEntity);
            esUserAuthUpdateProcessor.process(response);
            log.info("Profile Added Event Processed successfully for User Id : {}", profileAddedEvent.getUserId());
        }
    }
}
