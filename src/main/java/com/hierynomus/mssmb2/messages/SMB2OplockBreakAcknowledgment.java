package com.hierynomus.mssmb2.messages;

import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2FileId;
import com.hierynomus.mssmb2.SMB2MessageCommandCode;
import com.hierynomus.mssmb2.SMB2OplockBreakLevel;
import com.hierynomus.mssmb2.SMB2Packet;
import com.hierynomus.smb.SMBBuffer;

/**
 * [MS-SMB2].pdf 2.2.24 SMB2 OPLOCK_BREAK Acknowledgment
 */
public class SMB2OplockBreakAcknowledgment extends SMB2Packet {

    private SMB2OplockBreakLevel oplockLevel;
    private SMB2FileId fileId;

    public SMB2OplockBreakAcknowledgment(SMB2Dialect negotiatedDialect, long sessionId, long treeId, SMB2OplockBreakLevel oplockLevel, SMB2FileId fileId) {
        super(24, negotiatedDialect, SMB2MessageCommandCode.SMB2_OPLOCK_BREAK, sessionId, treeId);
        this.oplockLevel = oplockLevel;
        this.fileId = fileId;
    }

    @Override
    protected void writeTo(SMBBuffer buffer) {
        buffer.putUInt16(structureSize); // StructureSize (2 bytes)
        buffer.putByte((byte)oplockLevel.getValue()); // OpLockLevel (1 byte)
        buffer.putReserved1(); // Reserved (1 bytes)
        buffer.putReserved4(); // Reserved (4 bytes)
        fileId.write(buffer);  // FileId (16 bytes)
    }
}
