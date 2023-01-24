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

import java.io.FileDescriptor;
import java.util.Comparator;
import java.util.Map;
import java.util.WeakHashMap;

public class JDKContext extends AbstractContextImpl<JDKResource, Void> {

    private WeakHashMap<FileDescriptor, Object> claimedFds;

    static class ContextComparator implements Comparator<Map.Entry<JDKResource, Void>> {
        @Override
        public int compare(Map.Entry<JDKResource, Void> o1, Map.Entry<JDKResource, Void> o2) {
            return o1.getKey().getPriority().compareTo(o2.getKey().getPriority());
        }
    }

    JDKContext() {
        super(new ContextComparator());
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
        register(resource, null);
    }

    public WeakHashMap<FileDescriptor, Object> getClaimedFds() {
        return claimedFds;
    }

    public void claimFd(FileDescriptor fd, Object obj) {
        Object e = claimedFds.put(fd, obj);
        if (e != null) {
            throw new AssertionError(fd + " was already claimed by " + e);
        }
    }

    public boolean claimFdWeak(FileDescriptor fd, Object obj) {
        return claimedFds.putIfAbsent(fd, obj) == null;
    }
}
