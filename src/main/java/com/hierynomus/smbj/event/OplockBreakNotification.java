package com.hierynomus.smbj.event;

import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2OplockLevel;

public class OplockBreakNotification implements SMBEvent {

    private SMB2OplockLevel oplockLevel;
    private SMB2FileId fileId;

    public OplockBreakNotification(SMB2OplockLevel oplockLevel, SMB2FileId fileId) {
        this.oplockLevel = oplockLevel;
        this.fileId = fileId;
    }

    public SMB2OplockLevel getOplockLevel() {
        return oplockLevel;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }
}
