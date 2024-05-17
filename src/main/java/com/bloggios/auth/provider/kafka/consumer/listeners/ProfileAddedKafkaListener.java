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

package com.bloggios.auth.provider.kafka.consumer.listeners;

import com.bloggios.auth.provider.constants.BeanConstants;
import com.bloggios.auth.provider.constants.ExceptionCodes;
import com.bloggios.auth.provider.exception.payloads.InitializationException;
import com.bloggios.auth.provider.payload.IncomingMessage;
import com.bloggios.auth.provider.payload.event.ProfileAddedEvent;
import com.bloggios.auth.provider.processor.KafkaProcess;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.kafka.listener.ConsumerAwareMessageListener;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Owner - Rohit Parihar
 * Author - rohit
 * Project - auth-provider-application
 * Package - com.bloggios.auth.provider.kafka.consumer.listeners
 * Created_on - 17 March-2024
 * Created_at - 21 : 01
 */

@Component
public class ProfileAddedKafkaListener implements ConsumerAwareMessageListener<String, IncomingMessage> {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final KafkaProcess<ProfileAddedEvent> profileAddedEventListener;

    public ProfileAddedKafkaListener(
        @Qualifier(BeanConstants.PROFILE_ADDED_EVENT_LISTENER) KafkaProcess<ProfileAddedEvent> profileAddedEventListener
    ) {
        this.profileAddedEventListener = profileAddedEventListener;
    }

    @Override
    public void onMessage(ConsumerRecord<String, IncomingMessage> consumerRecord, Consumer<?, ?> consumer) {
        try {
            ProfileAddedEvent profileAddedEvent = objectMapper.readValue(objectMapper.writeValueAsBytes(consumerRecord.value().getMessageData().getData()), ProfileAddedEvent.class);
            profileAddedEventListener.process(profileAddedEvent);
        } catch (IOException exception) {
            throw new InitializationException(ExceptionCodes.JSON_DESERIALIZATION);
        }
        consumer.commitAsync();
    }
}
