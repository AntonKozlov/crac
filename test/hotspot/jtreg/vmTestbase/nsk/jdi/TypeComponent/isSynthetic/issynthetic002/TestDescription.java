/*
 * Copyright (c) 2018, 2024, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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


/*
 * @test
 *
 * @summary converted from VM Testbase nsk/jdi/TypeComponent/isSynthetic/issynthetic002.
 * VM Testbase keywords: [quick, jpda, jdi]
 * VM Testbase readme:
 * DESCRIPTION
 *     This test checks the isSynthetic() method of TypeComponent interface of
 *     com.sun.jdi package.
 *     The method spec:
 *     public boolean isSynthetic()
 *     Determines if this TypeComponent is synthetic. Synthetic members are
 *     generated by the compiler and are not present in the source code for the
 *     containing class.
 *     Not all target VMs support this query. See
 *     VirtualMachine.canGetSyntheticAttribute() to determine if the operation
 *     is supported.
 *     Returns: true if this type component is synthetic; false otherwise.
 *     Throws: java.lang.UnsupportedOperationException - if the target VM cannot
 *             provide information on synthetic attributes.
 *     nsk/jdi/TypeComponent/isSynthetic/issynthetic002 checks assertions:
 *     public java.lang.String isSynthetic()
 *     1. Returns true if the operation is supported and the method is synthetic;
 *     2. Returns false if the operation is supported and the method is not
 *        present in the source code for the containing class;
 *     3. Throws java.lang.UnsupportedOperationException if the target VM cannot
 *        provide information on synthetic attributes
 *        (VirtualMachine.canGetSyntheticAttribute() is false).
 *     4. Does not throw java.lang.UnsupportedOperationException if the target
 *        VM provides information on synthetic attributes
 *        (VirtualMachine.canGetSyntheticAttribute() is true).
 *     There are ClassToCheck and NestedClass declared within ClassToCheck in
 *     debugee. Nested class uses two private variables from ClassToCheck, so
 *     synthetic methods (two for each variable) must exist in ClassToCheck.
 *     Debugger gets all methods from debuggee, gets isSynthetic() value.
 *     If VirtualMachine.canGetSyntheticAttribute() is false then exception
 *     java.lang.UnsupportedOperationException must be thrown. Otherwise
 *     exception is not thrown.
 *     Then test tries to find method's name in list of methods that are present
 *     in the source code. If method is not found, then isSynthetic() value
 *     expects to be true, otherwise isSynthetic() value expects to be false.
 * COMMENTS
 *
 * @library /vmTestbase
 *          /test/lib
 * @build nsk.jdi.TypeComponent.isSynthetic.issynthetic002
 *        nsk.jdi.TypeComponent.isSynthetic.issynthetic002a
 * @run driver
 *      nsk.jdi.TypeComponent.isSynthetic.issynthetic002
 *      -verbose
 *      -arch=${os.family}-${os.simpleArch}
 *      -waittime=5
 *      -debugee.vmkind=java
 *      -transport.address=dynamic
 *      -debugee.vmkeys="${test.vm.opts} ${test.java.opts}"
 */

