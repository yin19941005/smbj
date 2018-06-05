/*
 * Copyright (C)2016 - SMBJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.hierynomus.mssmb2.messages.submodule;

import com.hierynomus.mssmb2.SMB2LockFlag;

import java.util.Set;

public class SMB2LockElement {
    private final long offset;
    private final long length;
    // TODO: Check valid combinations for lock flags
    private final Set<SMB2LockFlag> lockFlags;

    public SMB2LockElement(long offset, long length, Set<SMB2LockFlag> lockFlags) {
        this.offset = offset;
        this.length = length;
        this.lockFlags = lockFlags;
    }

    public long getOffset() {
        return offset;
    }

    public long getLength() {
        return length;
    }

    public Set<SMB2LockFlag> getLockFlags() {
        return lockFlags;
    }

    @Override
    public String toString() {
        return "SMB2LockElement{" + "offset=" + offset + ", length=" + length + ", lockFlags="
               + lockFlags + '}';
    }
}
