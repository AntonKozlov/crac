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

import jdk.crac.impl.PriorityContext;

import java.util.Comparator;

public class JDKContext extends PriorityContext<JDKResource.Priority, JDKResource> {
    // We cannot use method references/lambdas when the context is created
    public static final Comparator<JDKResource.Priority> PRIORITY_COMPARATOR = new Comparator<>() {
        @Override
        public int compare(JDKResource.Priority p1, JDKResource.Priority p2) {
            return p1.compareTo(p2);
        }
    };

    public JDKContext() {
        super(PRIORITY_COMPARATOR);
    }

    @Override
    public void register(JDKResource resource) {
        register(resource, resource.getPriority());
    }
}
