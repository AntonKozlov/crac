/*
 * Copyright (c) 2019, 2021, Azul Systems, Inc. All rights reserved.
 * Copyright (c) 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package jdk.internal.crac;

import jdk.crac.CheckpointException;
import jdk.crac.Context;
import jdk.crac.Resource;
import jdk.crac.RestoreException;
import jdk.crac.impl.AbstractContextImpl;
import jdk.internal.access.JavaIOFileDescriptorAccess;
import jdk.internal.access.SharedSecrets;
import sun.security.action.GetBooleanAction;

import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

public class JDKContext extends AbstractContextImpl<JDKResource, Void> {
    public static final String COLLECT_FD_STACKTRACES_PROPERTY = "jdk.crac.collect-fd-stacktraces";
    public static final String COLLECT_FD_STACKTRACES_HINT = "Use -D" + COLLECT_FD_STACKTRACES_PROPERTY + "=true to find the source.";

    // JDKContext by itself is initialized too early when system properties are not set yet
    public static class Properties {
        public static final boolean COLLECT_FD_STACKTRACES =
                GetBooleanAction.privilegedGetProperty(JDKContext.COLLECT_FD_STACKTRACES_PROPERTY);
    }

    private WeakHashMap<FileDescriptor, Object> claimedFds;

    public boolean matchClasspath(String path) {
        Path p = Path.of(path);
        String classpath = System.getProperty("java.class.path");
        int index = 0;
        while (index >= 0) {
            int end = classpath.indexOf(File.pathSeparatorChar, index);
            if (end < 0) {
                end = classpath.length();
            }
            try {
                if (Files.isSameFile(p, Path.of(classpath.substring(index, end)))) {
                    return true;
                }
            } catch (IOException e) {
                // ignore exception
                return false;
            }
        }
        return false;
    }

    JDKContext() {
    }

    @Override
    public synchronized void beforeCheckpoint(Context<? extends Resource> context) throws CheckpointException {
        claimedFds = new WeakHashMap<>();
        super.beforeCheckpoint(context);
    }

    @Override
    public synchronized void afterRestore(Context<? extends Resource> context) throws RestoreException {
        super.afterRestore(context);
        claimedFds = null;
    }

    @Override
    public void register(JDKResource resource) {
        register(resource, resource.getPriority().ordinal());
    }

    public Map<Integer, Object> getClaimedFds() {
        JavaIOFileDescriptorAccess fileDescriptorAccess = SharedSecrets.getJavaIOFileDescriptorAccess();
        return claimedFds.entrySet().stream()
                .collect(Collectors.toMap(entry -> fileDescriptorAccess.get(entry.getKey()), Map.Entry::getValue));
    }

    public void claimFd(FileDescriptor fd, Object obj) {
        if (!fd.valid()) {
            return;
        }
        Object e = claimedFds.put(fd, obj);
        if (e != null) {
            throw new AssertionError(fd + " was already claimed by " + e);
        }
    }

    public boolean claimFdWeak(FileDescriptor fd, Object obj) {
        if (fd == null || !fd.valid()) {
            return false;
        }
        return claimedFds.putIfAbsent(fd, obj) == null;
    }
}
