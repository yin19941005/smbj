package com.hierynomus.smbj.event;

import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2OplockBreakLevel;

public class OplockBreakNotification implements SMBEvent {

    private SMB2OplockBreakLevel oplockLevel;
    private SMB2FileId fileId;

    public OplockBreakNotification(SMB2OplockBreakLevel oplockLevel, SMB2FileId fileId) {
        this.oplockLevel = oplockLevel;
        this.fileId = fileId;
    }

    public SMB2OplockBreakLevel getOplockLevel() {
        return oplockLevel;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }
}
