package com.hierynomus.smbj.event;

import com.hierynomus.smbj.common.SmbPath;

/***
 * Event for notifying the SmbPath to DiskShare Notification Handler
 */
public class AsyncCreateRequestNotification implements SMBEvent, AsyncNotification {

    private long messageId;
    private SmbPath path;

    public AsyncCreateRequestNotification(long messageId, SmbPath path) {
        this.messageId = messageId;
        this.path = path;
    }

    public long getMessageId() {
        return messageId;
    }

    public SmbPath getPath() {
        return path;
    }
}
