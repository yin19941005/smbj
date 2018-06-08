package com.hierynomus.smbj.event.handler;

import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2OplockBreakLevel;
import com.hierynomus.mssmb2.messages.SMB2CreateResponse;

import java.util.concurrent.Future;

public interface OplockBreakNotificationHandler {
    void handle(OplockBreakNotificationHandlerType type,
                SMB2OplockBreakLevel oplockBreakLevel,
                SMB2FileId fileId,
                Future<SMB2CreateResponse> future);
}
