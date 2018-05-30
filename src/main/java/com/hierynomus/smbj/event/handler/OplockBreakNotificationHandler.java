package com.hierynomus.smbj.event.handler;

import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2OplockBreakLevel;
import com.hierynomus.mssmb2.SMB2OplockLevel;

public interface OplockBreakNotificationHandler {
    void handle(OplockBreakNotificationHandlerType type,
                       SMB2OplockBreakLevel oplockBreakLevel,
                       SMB2FileId fileId,
                       SMB2OplockLevel levelBeforeBreak);
}
