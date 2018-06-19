package com.hierynomus.smbj.event;

import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2CreateResponse;

import java.util.concurrent.Future;

/***
 * Event for notifying there are new create response granted oplock.
 */
public class AsyncCreateResponsePending implements SMBEvent {

    private long messageId;
    private SMB2FileId fileId;
    private Future<SMB2CreateResponse> future;

    public AsyncCreateResponsePending(long messageId, SMB2FileId fileId, Future<SMB2CreateResponse> future) {
        this.messageId = messageId;
        this.fileId = fileId;
        this.future = future;
    }

    public long getMessageId() {
        return messageId;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

    public Future<SMB2CreateResponse> getFuture() {
        return future;
    }
}
