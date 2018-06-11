package com.hierynomus.smbj.event.handler;

import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2OplockBreakLevel;
import com.hierynomus.mssmb2.messages.SMB2CreateResponse;
import com.hierynomus.smbj.common.SmbPath;

import java.util.concurrent.Future;

public interface NotificationHandler {
    void handle(NotificationMessageType type,
                long messageId,
                SMB2FileId fileId,
                SmbPath path,
                Future<SMB2CreateResponse> future,
                SMB2OplockBreakLevel oplockBreakLevel);
}
