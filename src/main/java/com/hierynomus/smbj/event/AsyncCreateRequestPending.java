package com.hierynomus.smbj.event;

import com.hierynomus.smbj.common.SmbPath;

public class AsyncCreateRequestPending implements SMBEvent {

    private long messageId;
    private SmbPath path;

    public AsyncCreateRequestPending(long messageId, SmbPath path) {
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
