package com.hierynomus.smbj.event;

import com.hierynomus.mssmb2.SMB2FileId;

/***
 * Event for notifying there are new create response granted oplock.
 */
public class CreateResponsePendingWithOplock implements SMBEvent {

    private SMB2FileId fileId;

    public CreateResponsePendingWithOplock(SMB2FileId fileId) {
        this.fileId = fileId;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }
}
