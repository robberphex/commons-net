/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.commons.net.util;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.LongStream;

import org.apache.commons.net.util.SubnetUtils.SubnetInfo;
import org.junit.jupiter.api.Test;

/**
 * Tests {@link SubnetUtils}.
 */
@SuppressWarnings("deprecation") // deliberate use of deprecated methods
public class SubnetUtilsIPv6Test {

    @Test
    public void testAddresses() {
        final SubnetUtils utils = new SubnetUtils("fd00::/126");
        final SubnetInfo info = utils.getInfo();
        assertTrue(info.isInRange("fd00::0"));
        assertTrue(info.isInRange("fd00::1"));
        assertTrue(info.isInRange("fd00::2"));
        assertTrue(info.isInRange("fd00::3"));

        assertFalse(info.isInRange("fd00::4"));
        assertFalse(info.isInRange("fd00::100"));
        assertFalse(info.isInRange("fd00::10f"));
        assertFalse(info.isInRange("fd00::2:1"));
        assertFalse(info.isInRange("fd00::1:1"));
        //
        assertThrows(UnsupportedOperationException.class, () -> info.asInteger("bad"));
        //
        assertEquals(BigInteger.valueOf(4), info.getAddressCountBigInteger());
        final List<String> actualAddresses = info.streamAddressStrings().collect(Collectors.toList());
        final List<String> expectedAddresses = new ArrayList<String>() {{
            add("fd00::");
            add("fd00::1");
            add("fd00::2");
            add("fd00::3");
        }};
        assertEquals(expectedAddresses, actualAddresses);
    }

    @Test
    public void testAddressIllegalArgument() {
        assertThrows(IllegalArgumentException.class, () -> new SubnetUtils("bad"));
    }

    /**
     * Test using the inclusiveHostCount flag, which includes the network and broadcast addresses in host counts
     */
    @Test
    public void testCidrAddresses() {
        //Valid address test
        final SubnetUtils subnetUtils = new SubnetUtils("2001:db8:3c0d:5b6d:0:0:42:8329/58");
        final SubnetInfo subnetInfo = subnetUtils.getInfo();
        assertEquals("2001:db8:3c0d:5b6d::42:8329/58", subnetInfo.getCIDRNotation(), "CIDR-Notation");
        assertEquals("2001:db8:3c0d:5b40::", subnetInfo.getLowAddress(), "Lowest Address");
        assertEquals("2001:db8:3c0d:5b7f:ffff:ffff:ffff:ffff", subnetInfo.getHighAddress(), "Highest Address");
        assertEquals(new BigInteger("1180591620717411303424"), subnetInfo.getAddressCountBigInteger(), "Address counts");
    }

    @Test
    public void testInvalidMasks() {
        assertThrows(IllegalArgumentException.class, () -> new SubnetUtils("::/"));
        assertThrows(IllegalArgumentException.class, () -> new SubnetUtils("fd00::/129"));
        assertThrows(IllegalArgumentException.class, () -> new SubnetUtils("fd00::/222"));
        assertThrows(IllegalArgumentException.class, () -> new SubnetUtils("fd00::/0128"));
    }

    @Test
    public void testNext() {
        final SubnetUtils utils = new SubnetUtils("fd00::1/126");
        assertEquals("fd00::2", utils.getNext().getInfo().getAddress());
    }

    @Test
    public void testPrevious() {
        final SubnetUtils utils = new SubnetUtils("fd00::2/126");
        assertEquals("fd00::1", utils.getPrevious().getInfo().getAddress());
    }

    @Test
    public void testSubnetAddressIterable() {
        testSubnetAddressIterable("fd00::/120", 256);
    }

    private void testSubnetAddressIterable(final String cidrNotation, final long max) {
        final SubnetUtils subnetUtils = new SubnetUtils(cidrNotation);
        final List<String> addressList = new ArrayList<>();
        subnetUtils.getInfo().iterableAddressStrings().forEach(addressList::add);
        assertEquals(max, addressList.size());
        LongStream.rangeClosed(1, max - 1).forEach(i -> {
            final String toContainsAddr = "fd00::" + Long.toHexString(i);
            assertTrue(addressList.contains(toContainsAddr), toContainsAddr + " should contained");
        });
        assertTrue(addressList.contains("fd00::"));
        assertFalse(addressList.contains("fd00::1:0"));
    }

    @Test
    public void testSubnetAddressStream() {
        testSubnetAddressStream("fd00::1:0/120", 256);
    }

    private void testSubnetAddressStream(final String cidrNotation, final long max) {
        final SubnetUtils subnetUtils = new SubnetUtils(cidrNotation);
        @SuppressWarnings("resource") final List<String> addressList = subnetUtils.getInfo().streamAddressStrings().collect(Collectors.toList());
        assertEquals(max, addressList.size());
        LongStream.rangeClosed(1, max - 1).forEach(i -> {
            final String toContainsAddr = "fd00::1:" + Long.toHexString(i);
            assertTrue(addressList.contains(toContainsAddr), toContainsAddr + " should contained");
        });
        assertTrue(addressList.contains("fd00::1:0"));
        assertFalse(addressList.contains("fd00::2:0"));
    }

    @Test
    public void testToString() {
        final SubnetUtils utils = new SubnetUtils("fd00::1/125");
        assertDoesNotThrow(() -> utils.toString());
        final SubnetInfo info = utils.getInfo();
        assertDoesNotThrow(() -> info.toString());
    }

}
