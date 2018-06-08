package com.hierynomus.smbj.event;

import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.messages.SMB2CreateResponse;

import java.util.concurrent.Future;

/***
 * Event for notifying there are new create response granted oplock.
 */
public class CreateResponsePendingWithOplock implements SMBEvent {

    private SMB2FileId fileId;
    private Future<SMB2CreateResponse> future;

    public CreateResponsePendingWithOplock(SMB2FileId fileId, Future<SMB2CreateResponse> future) {
        this.fileId = fileId;
        this.future = future;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

    public Future<SMB2CreateResponse> getFuture() {
        return future;
    }
}
