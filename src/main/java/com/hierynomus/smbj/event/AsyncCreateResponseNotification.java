/*
 * Copyright (C)2016 - SMBJ Contributors
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
package com.hierynomus.smbj.event;

import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2CreateResponse;

/***
 * Event for notifying the fileId and CreateResponseFuture to corresponding messageId on AysncCreate
 */
public class AsyncCreateResponseNotification extends AbstractAsyncResponseNotification
    implements SMBEvent {

    private SMB2FileId fileId;
    private SMB2CreateResponse createResponse;

    public AsyncCreateResponseNotification(long messageId, SMB2FileId fileId,
                                           SMB2CreateResponse createResponse) {
        super(messageId);
        this.fileId = fileId;
        this.createResponse = createResponse;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

    public SMB2CreateResponse getCreateResponse() {
        return createResponse;
    }
}
