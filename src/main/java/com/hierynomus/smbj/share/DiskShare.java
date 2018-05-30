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
package com.hierynomus.smbj.share;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SecurityDescriptor;
import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.mserref.NtStatus;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.FileSystemInformationClass;
import com.hierynomus.msfscc.fileinformation.*;
import com.hierynomus.mssmb2.*;
import com.hierynomus.mssmb2.messages.SMB2CreateResponse;
import com.hierynomus.mssmb2.messages.SMB2QueryInfoRequest;
import com.hierynomus.mssmb2.messages.SMB2SetInfoRequest;
import com.hierynomus.protocol.commons.EnumWithValue;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.protocol.transport.TransportException;
import com.hierynomus.smb.SMBBuffer;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.common.SMBRuntimeException;
import com.hierynomus.smbj.common.SmbPath;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.event.CreateResponsePendingWithOplock;
import com.hierynomus.smbj.event.OplockBreakNotification;
import com.hierynomus.smbj.event.SMBEventBus;
import com.hierynomus.smbj.event.handler.OplockBreakNotificationHandler;
import com.hierynomus.smbj.paths.PathResolveException;
import com.hierynomus.smbj.paths.PathResolver;
import com.hierynomus.smbj.session.Session;

import net.engio.mbassy.listener.Handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static com.hierynomus.msdtyp.AccessMask.*;
import static com.hierynomus.mserref.NtStatus.*;
import static com.hierynomus.msfscc.FileAttributes.FILE_ATTRIBUTE_DIRECTORY;
import static com.hierynomus.msfscc.FileAttributes.FILE_ATTRIBUTE_NORMAL;
import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_CREATE;
import static com.hierynomus.mssmb2.SMB2CreateDisposition.FILE_OPEN;
import static com.hierynomus.mssmb2.SMB2CreateOptions.FILE_DIRECTORY_FILE;
import static com.hierynomus.mssmb2.SMB2CreateOptions.FILE_NON_DIRECTORY_FILE;
import static com.hierynomus.mssmb2.SMB2ShareAccess.*;
import static com.hierynomus.mssmb2.messages.SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_SECURITY;


import static com.hierynomus.smbj.event.handler.OplockBreakNotificationHandlerType
    .SMB2_CREATE_RESPONSE;
import static com.hierynomus.smbj.event.handler.OplockBreakNotificationHandlerType
    .SMB2_OPLOCK_BREAK_NOTIFICATION;
import static java.util.EnumSet.of;
import static java.util.EnumSet.noneOf;

public class DiskShare extends Share {
    private static final Logger logger = LoggerFactory.getLogger(DiskShare.class);
    private final PathResolver resolver;
    private SMBEventBus bus;
    private OplockBreakNotificationHandler oplockBreakNotificationHandler = null;
    // the Map for handler in diskShare to use to notify the client the oplockBreakNotification for corresponding File instance
    private final ConcurrentHashMap<String, DiskEntry> openedFileMap = new ConcurrentHashMap<>();
    // TODO: Check is createResponsePendingWithOplockMap is required Map, or just List is OK.
    // the Map for tracking the createResponse status as exact as in TCP/IP layer to ensure the oplockBreakNotification handling correct
    private final ConcurrentHashMap<String, String> createResponsePendingWithOplockMap = new ConcurrentHashMap<>();

    public DiskShare(SmbPath smbPath, TreeConnect treeConnect, PathResolver pathResolver, SMBEventBus bus) {
        super(smbPath, treeConnect);
        this.resolver = pathResolver;
        this.bus = bus;
        if (bus != null) {
            bus.subscribe(this);
        }
    }

    public DiskEntry open(String path, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        return open(path, null, null, accessMask, attributes, shareAccesses, createDisposition, createOptions);
    }

    public DiskEntry open(String path, SMB2OplockLevel oplockLevel, SMB2ImpersonationLevel impersonationLevel, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        SmbPath pathAndFile = new SmbPath(smbPath, path);
        SMB2CreateResponseContext response = createFileAndResolve(pathAndFile, oplockLevel, impersonationLevel, accessMask, attributes, shareAccesses, createDisposition, createOptions);
        DiskEntry diskEntry = getDiskEntry(path, response);
        final SMB2FileId fileId = response.resp.getFileId();
        // record the map for fileId and File instance, i.e. record it as openedFile
        openedFileMap.put(fileId.toHexString(), diskEntry);
        // Removing the pending status for create Response
        createResponsePendingWithOplockMap.remove(fileId.toHexString());
        return diskEntry;
    }

    @Override
    protected Set<NtStatus> getCreateSuccessStatus() {
        return resolver.handledStates();
    }

    private SMB2CreateResponseContext createFileAndResolve(SmbPath path, SMB2OplockLevel oplockLevel, SMB2ImpersonationLevel impersonationLevel, Set<AccessMask> accessMask, Set<FileAttributes> fileAttributes, Set<SMB2ShareAccess> shareAccess, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        SMB2CreateResponse resp = super.createFile(path, oplockLevel, impersonationLevel, accessMask, fileAttributes, shareAccess, createDisposition, createOptions);
        try {
            SmbPath target = resolver.resolve(session, resp, path);
            DiskShare resolveShare = this;
            Session connectedSession = this.session;
            if (!path.isOnSameHost(target)) {
                connectedSession = buildNewSession(resp, target);
            }
            if (!path.isOnSameShare(target)) {
                resolveShare = (DiskShare) connectedSession.connectShare(target.getShareName());
            }
            if (!path.equals(target)) {
                return resolveShare.createFileAndResolve(target, oplockLevel, impersonationLevel, accessMask, fileAttributes, shareAccess, createDisposition, createOptions);
            }
        } catch (PathResolveException e) {
            throw new SMBApiException(e.getStatus(), SMB2MessageCommandCode.SMB2_CREATE, "Cannot resolve path " + path, e);
        }
        return new SMB2CreateResponseContext(resp, this);
    }

    private Session buildNewSession(SMB2CreateResponse resp, SmbPath target) {
        SMBClient client = treeConnect.getConnection().getClient();
        try {
            Connection connect = client.connect(target.getHostname());
            return connect.authenticate(session.getAuthenticationContext());
        } catch (IOException e) {
            throw new SMBApiException(resp.getHeader(), "Cannot connect to resolved path " + target, e);
        }
    }

    protected DiskEntry getDiskEntry(String path, SMB2CreateResponseContext responseContext) {
        SMB2CreateResponse response = responseContext.resp;
        if (response.getFileAttributes().contains(FILE_ATTRIBUTE_DIRECTORY)) {
            return new Directory(response.getFileId(), responseContext.share, path, response.getOplockLevel());
        } else {
            return new File(response.getFileId(), responseContext.share, path, response.getOplockLevel());
        }
    }

    /**
     * Get a handle to a directory in the given path
     */
    public Directory openDirectory(String path, SMB2OplockLevel oplockLevel, SMB2ImpersonationLevel impersonationLevel, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        EnumSet<SMB2CreateOptions> actualCreateOptions = createOptions != null ? EnumSet.copyOf(createOptions) : EnumSet.noneOf(SMB2CreateOptions.class);
        actualCreateOptions.add(FILE_DIRECTORY_FILE);
        actualCreateOptions.remove(FILE_NON_DIRECTORY_FILE);

        EnumSet<FileAttributes> actualAttributes = attributes != null ? EnumSet.copyOf(attributes) : EnumSet.noneOf(FileAttributes.class);
        actualAttributes.add(FILE_ATTRIBUTE_DIRECTORY);

        return (Directory) open(
            path,
            oplockLevel,
            impersonationLevel,
            accessMask,
            actualAttributes,
            shareAccesses,
            createDisposition,
            actualCreateOptions
        );
    }

    public File openFile(String path, SMB2OplockLevel oplockLevel, SMB2ImpersonationLevel impersonationLevel, Set<AccessMask> accessMask, Set<FileAttributes> attributes, Set<SMB2ShareAccess> shareAccesses, SMB2CreateDisposition createDisposition, Set<SMB2CreateOptions> createOptions) {
        EnumSet<SMB2CreateOptions> actualCreateOptions = createOptions != null ? EnumSet.copyOf(createOptions) : EnumSet.noneOf(SMB2CreateOptions.class);
        actualCreateOptions.add(FILE_NON_DIRECTORY_FILE);
        actualCreateOptions.remove(FILE_DIRECTORY_FILE);

        EnumSet<FileAttributes> actualAttributes = attributes != null ? EnumSet.copyOf(attributes) : EnumSet.noneOf(FileAttributes.class);
        actualAttributes.remove(FILE_ATTRIBUTE_DIRECTORY);

        return (File) open(
            path,
            oplockLevel,
            impersonationLevel,
            accessMask,
            actualAttributes,
            shareAccesses,
            createDisposition,
            actualCreateOptions
        );
    }

    /***
     * Closing the file by fileId and remove it from the openedFileMap.
     * @param fileId the fileId of the target to close file
     * @throws SMBApiException
     */
    @Override
    void closeFileId(SMB2FileId fileId) throws SMBApiException {
        super.closeFileId(fileId);
        openedFileMap.remove(fileId.toHexString());
    }

    /**
     * File in the given path exists or not
     */
    public boolean fileExists(String path) throws SMBApiException {
        return exists(path, of(FILE_NON_DIRECTORY_FILE), of(STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_FILE_IS_A_DIRECTORY));
    }

    /**
     * Folder in the given path exists or not.
     */
    public boolean folderExists(String path) throws SMBApiException {
        return exists(path, of(FILE_DIRECTORY_FILE), of(STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_NOT_A_DIRECTORY));
    }

    private boolean exists(String path, EnumSet<SMB2CreateOptions> createOptions, Set<NtStatus> acceptedStatuses) throws SMBApiException {
        try (DiskEntry ignored = open(path, null, null, of(FILE_READ_ATTRIBUTES), of(FILE_ATTRIBUTE_NORMAL), ALL, FILE_OPEN, createOptions)) {
            return true;
        } catch (SMBApiException sae) {
            if (acceptedStatuses.contains(sae.getStatus())) {
                return false;
            } else {
                throw sae;
            }
        }
    }

    /**
     * Equivalent to calling {@link #list(String, Class, String) list(path, FileIdBothDirectoryInformation.class, null)}.
     *
     * @see #list(String, Class, String)
     */
    public List<FileIdBothDirectoryInformation> list(String path) throws SMBApiException {
        return list(path, FileIdBothDirectoryInformation.class, null);
    }

    /**
     * Equivalent to calling {@link #list(String, Class, String) list(path, FileIdBothDirectoryInformation.class, searchPattern)}.
     *
     * @see #list(String, Class, String)
     */
    public List<FileIdBothDirectoryInformation> list(String path, String searchPattern) throws SMBApiException {
        return list(path, FileIdBothDirectoryInformation.class, searchPattern);
    }

    /**
     * Equivalent to calling {@link #list(String, Class, String) list(path, informationClass, null)}.
     *
     * @see #list(String, Class, String)
     */
    public <I extends FileDirectoryQueryableInformation> List<I> list(String path, Class<I> informationClass) {
        return list(path, informationClass, null);
    }

    /**
     * Opens the given path for read-only access and performs a directory listing.
     *
     * @see Directory#iterator(Class, String)
     */
    public <I extends FileDirectoryQueryableInformation> List<I> list(String path, Class<I> informationClass, String searchPattern) {
        try (Directory d = openDirectory(path, null, null, of(FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_EA), null, ALL, FILE_OPEN, null)) {
            return d.list(informationClass, searchPattern);
        }
    }

    /**
     * Create a directory in the given path.
     */
    public void mkdir(String path) throws SMBApiException {
        Directory fileHandle = openDirectory(
            path,
            null,
            null,
            of(FILE_LIST_DIRECTORY, FILE_ADD_SUBDIRECTORY),
            of(FILE_ATTRIBUTE_DIRECTORY),
            ALL,
            FILE_CREATE,
            of(FILE_DIRECTORY_FILE));
        fileHandle.close();
    }

    /**
     * Get information about the given path.
     **/
    public FileAllInformation getFileInformation(String path) throws SMBApiException {
        return getFileInformation(path, FileAllInformation.class);
    }

    /**
     * Get information about the given path.
     **/
    public <F extends FileQueryableInformation> F getFileInformation(String path, Class<F> informationClass) throws SMBApiException {
        try (DiskEntry e = open(path, null, null, of(FILE_READ_ATTRIBUTES, FILE_READ_EA), null, ALL, FILE_OPEN, null)) {
            return e.getFileInformation(informationClass);
        }
    }

    /**
     * Get information for a given fileId
     **/
    public FileAllInformation getFileInformation(SMB2FileId fileId) throws SMBApiException, TransportException {
        return getFileInformation(fileId, FileAllInformation.class);
    }

    public <F extends FileQueryableInformation> F getFileInformation(SMB2FileId fileId, Class<F> informationClass) throws SMBApiException {
        FileInformation.Decoder<F> decoder = FileInformationFactory.getDecoder(informationClass);

        byte[] outputBuffer = queryInfo(
            fileId,
            SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_FILE,
            null,
            decoder.getInformationClass(),
            null
        ).getOutputBuffer();

        try {
            return decoder.read(new Buffer.PlainBuffer(outputBuffer, Endian.LE));
        } catch (Buffer.BufferException e) {
            throw new SMBRuntimeException(e);
        }
    }

    public <F extends FileSettableInformation> void setFileInformation(SMB2FileId fileId, F information) {
        SMBBuffer buffer = new SMBBuffer();
        FileInformation.Encoder<F> encoder = FileInformationFactory.getEncoder(information);
        encoder.write(information, buffer);

        setInfo(
            fileId,
            SMB2SetInfoRequest.SMB2InfoType.SMB2_0_INFO_FILE,
            null,
            encoder.getInformationClass(),
            buffer.getCompactData()
        );
    }

    /**
     * Get information for a given path
     **/
    public <F extends FileSettableInformation> void setFileInformation(String path, F information) throws SMBApiException {
        try (DiskEntry e = open(path, null, null, of(FILE_WRITE_ATTRIBUTES, FILE_WRITE_EA), null, ALL, FILE_OPEN, null)) {
            e.setFileInformation(information);
        }
    }

    /**
     * Get Share Information for the current Disk Share
     *
     * @return the ShareInfo
     */
    public ShareInfo getShareInformation() throws SMBApiException {
        try (Directory directory = openDirectory("", null, null, of(FILE_READ_ATTRIBUTES), null, ALL, FILE_OPEN, null)) {
            byte[] outputBuffer = queryInfo(
                directory.getFileId(),
                SMB2QueryInfoRequest.SMB2QueryInfoType.SMB2_0_INFO_FILESYSTEM,
                null,
                null,
                FileSystemInformationClass.FileFsFullSizeInformation
            ).getOutputBuffer();

            try {
                return ShareInfo.parseFsFullSizeInformation(new Buffer.PlainBuffer(outputBuffer, Endian.LE));
            } catch (Buffer.BufferException e) {
                throw new SMBRuntimeException(e);
            }
        }
    }

    /**
     * Remove the directory at the given path.
     */
    public void rmdir(String path, boolean recursive) throws SMBApiException {
        if (recursive) {
            List<FileIdBothDirectoryInformation> list = list(path);
            for (FileIdBothDirectoryInformation fi : list) {
                if (fi.getFileName().equals(".") || fi.getFileName().equals("..")) {
                    continue;
                }
                String childPath = path + "\\" + fi.getFileName();
                if (!EnumWithValue.EnumUtils.isSet(fi.getFileAttributes(), FILE_ATTRIBUTE_DIRECTORY)) {
                    rm(childPath);
                } else {
                    rmdir(childPath, true);
                }
            }
            rmdir(path, false);
        } else {
            try (DiskEntry e = open(
                path,
                null,
                null,
                of(DELETE),
                of(FILE_ATTRIBUTE_DIRECTORY),
                of(FILE_SHARE_DELETE, FILE_SHARE_WRITE, FILE_SHARE_READ),
                FILE_OPEN,
                of(FILE_DIRECTORY_FILE)
            )) {
                e.deleteOnClose();
            }
        }
    }

    /**
     * Remove the file at the given path
     */
    public void rm(String path) throws SMBApiException {
        try (DiskEntry e = open(
            path,
            null,
            null,
            of(DELETE),
            of(FILE_ATTRIBUTE_NORMAL),
            of(FILE_SHARE_DELETE, FILE_SHARE_WRITE, FILE_SHARE_READ),
            FILE_OPEN,
            of(FILE_NON_DIRECTORY_FILE)
        )) {
            e.deleteOnClose();
        }
    }

    public void deleteOnClose(SMB2FileId fileId) {
        setFileInformation(fileId, new FileDispositionInformation(true));
    }

    /**
     * The SecurityDescriptor(MS-DTYP 2.4.6 SECURITY_DESCRIPTOR) for the Given Path
     */
    public SecurityDescriptor getSecurityInfo(String path, Set<SecurityInformation> securityInfo) throws SMBApiException {
        EnumSet<AccessMask> accessMask = of(READ_CONTROL);
        if (securityInfo.contains(SecurityInformation.SACL_SECURITY_INFORMATION)) {
            accessMask.add(ACCESS_SYSTEM_SECURITY);
        }

        try (DiskEntry e = open(path, null, null, accessMask, null, ALL, FILE_OPEN, null)) {
            return e.getSecurityInformation(securityInfo);
        }
    }

    /**
     * The SecurityDescriptor(MS-DTYP 2.4.6 SECURITY_DESCRIPTOR) for the Given FileId
     */
    public SecurityDescriptor getSecurityInfo(SMB2FileId fileId, Set<SecurityInformation> securityInfo) throws SMBApiException {

        byte[] outputBuffer = queryInfo(fileId, SMB2_0_INFO_SECURITY, securityInfo, null, null).getOutputBuffer();
        try {
            return SecurityDescriptor.read(new SMBBuffer(outputBuffer));
        } catch (Buffer.BufferException e) {
            throw new SMBRuntimeException(e);
        }
    }

    /**
     * The SecurityDescriptor(MS-DTYP 2.4.6 SECURITY_DESCRIPTOR) for the Given FileId
     */
    public void setSecurityInfo(String path, Set<SecurityInformation> securityInfo, SecurityDescriptor securityDescriptor) throws SMBApiException {
        Set<AccessMask> accessMask = noneOf(AccessMask.class);
        if (securityInfo.contains(SecurityInformation.SACL_SECURITY_INFORMATION)) {
            accessMask.add(ACCESS_SYSTEM_SECURITY);
        }
        if (securityInfo.contains(SecurityInformation.OWNER_SECURITY_INFORMATION) || securityInfo.contains(SecurityInformation. GROUP_SECURITY_INFORMATION)) {
            accessMask.add(WRITE_OWNER);
        }
        if (securityInfo.contains(SecurityInformation.DACL_SECURITY_INFORMATION)) {
            accessMask.add(WRITE_DAC);
        }

        try (DiskEntry e = open(path, null, null, accessMask, null, ALL, FILE_OPEN, null)) {
            e.setSecurityInformation(securityDescriptor, securityInfo);
        }
    }

    /**
     * The SecurityDescriptor(MS-DTYP 2.4.6 SECURITY_DESCRIPTOR) for the Given FileId
     */
    public void setSecurityInfo(SMB2FileId fileId, Set<SecurityInformation> securityInfo, SecurityDescriptor securityDescriptor) throws SMBApiException {
        SMBBuffer buffer = new SMBBuffer();
        securityDescriptor.write(buffer);

        setInfo(
            fileId,
            SMB2SetInfoRequest.SMB2InfoType.SMB2_0_INFO_SECURITY,
            securityInfo,
            null,
            buffer.getCompactData()
        );
    }

    /***
     * 3.2.5.19 Receiving an SMB2 OPLOCK_BREAK Notification, this handler is responsible to call acknowledgeOplockBreak if needed. Set the handler for Receiving an Oplock Break Notification.
     * You MUST set this handler before create/open diskEntry with oplock.
     *
     * @param handler handler for Receiving an Oplock Break Notification
     */
    public void setOplockBreakNotificationHandler(OplockBreakNotificationHandler handler) {
        this.oplockBreakNotificationHandler = handler;
    }

    /***
     * Handler for handing the oplock break notification event from server. 3.2.5.19 Receiving an SMB2 OPLOCK_BREAK Notification.
     *
     * @param oplockBreakNotification received oplock break notification from server.
     */
    @Handler
    @SuppressWarnings("unused")
    private void oplockBreakNotification(final OplockBreakNotification oplockBreakNotification) {
        try {

            final SMB2FileId fileId = oplockBreakNotification.getFileId();
            final SMB2OplockBreakLevel oplockLevel = oplockBreakNotification.getOplockLevel();

            // find the corresponding diskEntry instance
            if(!openedFileMap.containsKey(fileId.toHexString()) && !createResponsePendingWithOplockMap
                .containsKey(fileId.toHexString())) {
                // 3.2.5.19.1 Receiving an Oplock Break Notification
                // The client MUST locate the open in the Session.OpenTable using the FileId in the Oplock Break
                // Notification following the SMB2 header. If the open is not found, the oplock break indication MUST be
                // discarded, and no further processing is required.
            }else {
                DiskEntry diskEntry = openedFileMap.get(fileId.toHexString());
                if(diskEntry != null) {
                    logger.debug("FileId {} received OplockBreakNotification, Oplock level {}", fileId, oplockLevel);

                    final SMB2OplockLevel levelBeforeBreak = diskEntry.getOplockLevel();
                    diskEntry.setOplockBreakLevel(oplockLevel);

                    if(oplockBreakNotificationHandler != null) {
                        // Preventing the improper use of handler (holding the thread). if holding thread, timeout exception will be throw.
                        Thread t = new Thread(new Runnable() {
                            @Override
                            public void run() {
                                oplockBreakNotificationHandler.handle(SMB2_OPLOCK_BREAK_NOTIFICATION, oplockLevel, fileId, levelBeforeBreak);
                            }
                        });
                        t.start();
                    }else {
                        logger.warn("FileId {}, OplockBreakNotificationHandler not exist to handle Oplock Break.");
                        throw new IllegalStateException("OplockBreakNotificationHandler not exist to handle Oplock Break.");
                    }
                }else {
                    logger.warn("FileId {}, diskEntry not exist to handle Oplock Break.");
                    throw new IllegalStateException("diskEntry not exist to handle Oplock Break.");
                }
            }
        } catch (Throwable t) {
            logger.error("Handling oplockBreakNotification error occur : ", t);
            throw t;
        }
    }

    /***
     * Oplock related handler. Handler for handling create response granted oplock.
     * This is intended to prevent oplock break too fast and not able to handle oplock break notification properly.
     * Notify the client oplock is granted on createResponse but still under processing.
     *
     * @param createResponsePendingWithOplock the corresponding fileId had granted some level of oplock.
     */
    @Handler
    @SuppressWarnings("unused")
    private void createResponsePendingWithOplock(final CreateResponsePendingWithOplock createResponsePendingWithOplock) {
        // Put the fileId to createResponse pending map to indicate this is a create response granted oplock
        createResponsePendingWithOplockMap.put(createResponsePendingWithOplock.getFileId().toHexString(),
                                               createResponsePendingWithOplock.getFileId().toHexString());

        if(oplockBreakNotificationHandler != null) {
            // Preventing the improper use of handler (holding the thread). if holding thread, timeout exception will be throw.
            Thread t = new Thread(new Runnable() {
                @Override
                public void run() {
                    oplockBreakNotificationHandler.handle(SMB2_CREATE_RESPONSE, null, createResponsePendingWithOplock.getFileId(), null);
                }
            });
            t.start();
        }else {
            logger.warn("FileId {}, OplockBreakNotificationHandler not exist to handle Create Response with Oplock.");
            throw new IllegalStateException("OplockBreakNotificationHandler not exist to handle Create Response with Oplock.");
        }

    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getSmbPath() + "]";
    }

    /**
     * A return object for the {@link #createFileAndResolve(SmbPath, SMB2OplockLevel, SMB2ImpersonationLevel, Set, Set, Set, SMB2CreateDisposition, Set)} call.
     *
     * This object wraps the {@link SMB2CreateResponse} and the actual {@link Share} which generated it if the path needed to be resolved.
     */
    static class SMB2CreateResponseContext {
        final SMB2CreateResponse resp;
        final DiskShare share;

        public SMB2CreateResponseContext(SMB2CreateResponse resp, DiskShare share) {
            this.resp = resp;
            this.share = share;
        }
    }
}
