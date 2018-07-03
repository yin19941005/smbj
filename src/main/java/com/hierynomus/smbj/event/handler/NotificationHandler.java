package com.hierynomus.smbj.event.handler;

import com.hierynomus.smbj.event.AsyncNotification;

public interface NotificationHandler {
    void handle(NotificationMessageType type,
                AsyncNotification asyncNotification);
}
