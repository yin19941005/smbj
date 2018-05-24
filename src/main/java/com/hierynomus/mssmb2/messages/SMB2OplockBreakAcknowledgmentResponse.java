package com.hierynomus.mssmb2.messages;

import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2OplockLevel;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.smb.SMBBuffer;

public class SMB2OplockBreakAcknowledgmentResponse extends SMB2Packet {

    private SMB2OplockLevel oplockLevel;
    private SMB2FileId fileId;

    @Override
    protected void readMessage(SMBBuffer buffer) throws Buffer.BufferException {
        buffer.readUInt16(); // StructureSize (2 bytes)
        oplockLevel = EnumWithValue.EnumUtils.valueOf(buffer.readByte(), SMB2OplockLevel.class, SMB2OplockLevel.SMB2_OPLOCK_LEVEL_NONE); // OpLockLevel (1 byte)
        buffer.readByte(); // Reserved (1 byte)
        buffer.skip(4); // Reserved2 (4 bytes)
        fileId = SMB2FileId.read(buffer); // FileId (16 bytes)
    }

    public SMB2OplockLevel getOplockLevel() {
        return oplockLevel;
    }

    public SMB2FileId getFileId() {
        return fileId;
    }

}
