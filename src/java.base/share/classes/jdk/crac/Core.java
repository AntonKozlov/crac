/*
 * Copyright (c) 2017, 2021, Azul Systems, Inc. All rights reserved.
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

package jdk.crac;

import jdk.crac.impl.CheckpointOpenFileException;
import jdk.crac.impl.CheckpointOpenResourceException;
import jdk.crac.impl.CheckpointOpenSocketException;
import jdk.crac.impl.OrderedContext;
import sun.security.action.GetBooleanAction;

import java.util.Arrays;

/**
 * The coordination service.
 */
public class Core {
    private static final int JVM_CHECKPOINT_OK    = 0;
    private static final int JVM_CHECKPOINT_ERROR = 1;
    private static final int JVM_CHECKPOINT_NONE  = 2;

    private static final int JVM_CR_FAIL = 0;
    private static final int JVM_CR_FAIL_FILE = 1;
    private static final int JVM_CR_FAIL_SOCK = 2;
    private static final int JVM_CR_FAIL_PIPE = 3;

    private static native Object[] checkpointRestore0(boolean dryRun);

    private static final Object checkpointRestoreLock = new Object();
    private static boolean checkpointInProgress = false;

    private static String[] newArguments = {};

    private static class FlagsHolder {
        public static final boolean TRACE_STARTUP_TIME =
            GetBooleanAction.privilegedGetProperty("jdk.crac.trace-startup-time");
    }

    private static final Context<Resource> globalContext = new OrderedContext();
    static {
        // force JDK context initialization
        jdk.internal.crac.Core.getJDKContext();
    }

    /** This class is not instantiable. */
    private Core() {
    }

    private static void translateJVMExceptions(int[] codes, String[] messages,
                                               CheckpointException exception) {
        assert codes.length == messages.length;
        final int length = codes.length;

        for (int i = 0; i < length; ++i) {
            switch(codes[i]) {
                case JVM_CR_FAIL_FILE:
                    exception.addSuppressed(
                            new CheckpointOpenFileException(messages[i]));
                    break;
                case JVM_CR_FAIL_SOCK:
                    exception.addSuppressed(
                            new CheckpointOpenSocketException(messages[i]));
                    break;
                case JVM_CR_FAIL_PIPE:
                    // FALLTHROUGH
                default:
                    exception.addSuppressed(
                            new CheckpointOpenResourceException(messages[i]));
                    break;
            }
        }
    }

    /**
     * Gets the global {@code Context} for checkpoint/restore notifications.
     *
     * @return the global {@code Context}
     */
    public static Context<Resource> getGlobalContext() {
        return globalContext;
    }

    private static void checkpointRestore1() throws
            CheckpointException,
            RestoreException {
        CheckpointException checkpointException = null;

        try {
            globalContext.beforeCheckpoint(null);
        } catch (CheckpointException ce) {
            checkpointException = new CheckpointException();
            for (Throwable t : ce.getSuppressed()) {
                checkpointException.addSuppressed(t);
            }
        }

        final Object[] bundle = checkpointRestore0(checkpointException != null);
        final int retCode = (Integer)bundle[0];
        final String newArguments = (String)bundle[1];
        final int[] codes = (int[])bundle[2];
        final String[] messages = (String[])bundle[3];

        if (FlagsHolder.TRACE_STARTUP_TIME) {
            System.out.println("STARTUPTIME " + System.nanoTime() + " restore");
        }

        if (retCode != JVM_CHECKPOINT_OK) {
            if (checkpointException == null) {
                checkpointException = new CheckpointException();
            }
            switch (retCode) {
                case JVM_CHECKPOINT_ERROR:
                    translateJVMExceptions(codes, messages, checkpointException);
                    break;
                case JVM_CHECKPOINT_NONE:
                    checkpointException.addSuppressed(
                            new RuntimeException("C/R is not configured"));
                    break;
                default:
                    checkpointException.addSuppressed(
                            new RuntimeException("Unknown C/R result: " + retCode));
            }
        }

        if (checkpointException == null) {
            Core.newArguments = newArguments != null ? newArguments.split(" ") : new String[0];
        }

        try {
            globalContext.afterRestore(null);
        } catch (RestoreException re) {
            if (checkpointException == null) {
                throw re;
            }
            for (Throwable t : re.getSuppressed()) {
                checkpointException.addSuppressed(t);
            }
        }
        if (checkpointException != null) {
            throw checkpointException;
        }
    }

    /**
     * Requests checkpoint and returns upon a successful restore.
     * May throw an exception if the checkpoint or restore are unsuccessful.
     *
     * @throws CheckpointException if an exception occured during checkpoint
     * notification and the execution continues in the original Java instance.
     * @throws RestoreException if an exception occured during restore
     * notification and execution continues in a new Java instance.
     * @throws UnsupportedOperationException if checkpoint/restore is not
     * supported, no notification performed and the execution continues in
     * the original Java instance.
     */
    public static void checkpointRestore() throws
            CheckpointException,
            RestoreException {
        // checkpointRestore protects against the simultaneous
        // call of checkpointRestore from different threads.
        synchronized (checkpointRestoreLock) {
            // checkpointInProgress protects against recursive
            // checkpointRestore from resource's
            // beforeCheckpoint/afterRestore methods
            if (!checkpointInProgress) {
                try {
                    checkpointInProgress = true;
                    checkpointRestore1();
                } finally {
                    if (FlagsHolder.TRACE_STARTUP_TIME) {
                        System.out.println("STARTUPTIME " + System.nanoTime() + " restore-finish");
                    }
                    checkpointInProgress = false;
                }
            } else {
                throw new CheckpointException("Recursive checkpoint is not allowed");
            }
        }
    }

    /**
     * Gets new arguments provided after restore.
     *
     * @return new arguments
     */
    public static String[] newArguments() {
        return Arrays.copyOf(newArguments, newArguments.length);
    }

    /* called by VM */
    private static void checkpointRestoreInternal() {
        Thread thread = new Thread(() -> {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
            }

            try {
                checkpointRestore();
            } catch (CheckpointException | RestoreException e) {
                for (Throwable t : e.getSuppressed()) {
                    t.printStackTrace();
                }
            }
        });
        thread.setDaemon(true);
        thread.start();
    }
}
