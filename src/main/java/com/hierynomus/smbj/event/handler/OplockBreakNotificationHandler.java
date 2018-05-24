package com.hierynomus.smbj.event.handler;

import com.hierynomus.mssmb2.SMB2OplockLevel;
import com.hierynomus.smbj.event.OplockBreakNotification;

public interface OplockBreakNotificationHandler {
    public void handle(OplockBreakNotification oplockBreakNotification, SMB2OplockLevel levelBeforeBreak);
}
