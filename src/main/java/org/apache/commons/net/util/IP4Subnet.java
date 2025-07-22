/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.net.util;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * Convenience container for IPv4 subnet summary information.
 *
 * @see <a href="https://tools.ietf.org/html/rfc4632">https://tools.ietf.org/html/rfc4632</a>
 * @since 3.12
 */
public final class IP4Subnet extends SubnetUtils.SubnetInfo {
    /**
     * Allows an object to be the target of the "for-each loop" statement for a SubnetInfo.
     */
    private static final class SubnetAddressStringIterable implements Iterable<String> {

        private final IP4Subnet subnetInfo;

        /**
         * Constructs a new instance.
         *
         * @param subnetInfo the SubnetInfo to iterate.
         */
        private SubnetAddressStringIterable(final IP4Subnet subnetInfo) {
            this.subnetInfo = subnetInfo;
        }

        @Override
        public Iterator<String> iterator() {
            return new SubnetAddressStringIterator(subnetInfo);
        }
    }

    /**
     * Iterates over a SubnetInfo.
     */
    private static final class SubnetAddressStringIterator implements Iterator<String> {

        private int currentAddress;

        private final IP4Subnet subnetInfo;

        /**
         * Constructs a new instance.
         *
         * @param subnetInfo the SubnetInfo to iterate.
         */
        private SubnetAddressStringIterator(final IP4Subnet subnetInfo) {
            this.subnetInfo = subnetInfo;
            currentAddress = subnetInfo.low();
        }

        @Override
        public boolean hasNext() {
            return subnetInfo.getAddressCountLong() > 0 && currentAddress <= subnetInfo.high();
        }

        @Override
        public String next() {
            return format(toArray4(currentAddress++));
        }
    }

    /* Mask to convert an unsigned integer to a long (e.g. keep 32 bits) */
    private static final long UNSIGNED_INT_MASK = 0x0FFFFFFFFL;
    private static final int NBITS = 32;

    private final int address;
    private final int cidr;
    private final int netmask;
    private final int network;
    private final int broadcast;

    /**
     * Whether the broadcast/network addresses are included in host count
     */
    private boolean inclusiveHostCount;

    /**
     * Constructor that takes CIDR-notation, e.g. "192.168.0.1/16".
     *
     * @param addr an IPv4 address in CIDR-notation
     * @param cidr the CIDR prefix size
     * @throws IllegalArgumentException if the parameter is invalid,
     * e.g. does not match n.n.n.n/m where n=1-3 decimal digits, m is in range 0-32
     */
    public IP4Subnet(String addr, int cidr) {
        this.address = toInteger(addr);

        /* Create a network prefix, CIDR, from the number of bits specification /x  */
        this.cidr = rangeCheck(cidr, 0, NBITS);

        /*
         * An IPv4 netmask consists of 32 bits, a contiguous sequence
         * of the specified number of ones followed by all zeros.
         * So, it can be obtained by shifting an unsigned integer (32 bits) to the left by
         * the number of trailing zeros which is (32 - the # bits specification).
         * Note that there is no unsigned left shift operator, so we have to use
         * a long to ensure that the left-most bit is shifted out correctly.
         */
        this.netmask = (int) (UNSIGNED_INT_MASK << (NBITS - cidr));

        /* Calculate base network address */
        this.network = address & netmask;

        /* Calculate broadcast address */
        this.broadcast = network | ~netmask;
    }

    /**
     * Constructor that takes a dotted decimal address and a dotted decimal mask.
     *
     * @param address an IPv4 address, e.g. "192.168.0.1"
     * @param mask a dotted decimal netmask e.g. "255.255.0.0"
     * @throws IllegalArgumentException if the address or mask is invalid,
     * i.e. does not match n.n.n.n where n=1-3 decimal digits and the mask is not all zeros.
     */
    public IP4Subnet(String address, String mask) {
        this.address = toInteger(address);
        this.netmask = toInteger(mask);

        /*
         * An IPv4 subnet mask must consist of a set of contiguous 1-bits followed by a block of 0-bits.
         * If the mask follows the format, the numbers of subtracting one from the lowest one bit of the mask,
         * see Hacker's Delight section 2.1, equals to the bitwise complement of the mask.
         */
        if ((this.netmask & -this.netmask) - 1 != ~this.netmask) {
            throw new IllegalArgumentException("Could not parse [" + mask + "]");
        }

        this.cidr = pop(this.netmask);

        /* Calculate base network address */
        this.network = this.address & this.netmask;

        /* Calculate broadcast address */
        this.broadcast = this.network | ~(this.netmask);
    }

    /**
     * Returns {@code true} if the return value of {@link #getAddressCountLong() getAddressCountLong}
     * includes the network and broadcast addresses.
     *
     * @return {@code true} if the host count includes the network and broadcast addresses
     */
    @Override
    public boolean isInclusiveHostCount() {
        return inclusiveHostCount;
    }

    /**
     * Sets to {@code true} if you want the return value of {@link #getAddressCountLong() getAddressCountLong}
     * to include the network and broadcast addresses.
     *
     * @param inclusiveHostCount {@code true} if network and broadcast addresses are to be included
     */
    @Override
    public void setInclusiveHostCount(boolean inclusiveHostCount) {
        this.inclusiveHostCount = inclusiveHostCount;
    }

    /* long versions of the values (as unsigned int) which are more suitable for range checking */
    private long networkLong() {
        return network & UNSIGNED_INT_MASK;
    }

    private long broadcastLong() {
        return broadcast & UNSIGNED_INT_MASK;
    }

    /*
     * Creates the minimum address in the network to which the address belongs.
     *
     * inclusiveHostCount
     *  - true: the network address
     *  - false: the first address of the available as host addresses or 0 if no corresponding address
     */
    private int low() {
        return inclusiveHostCount ? network : (broadcastLong() - networkLong()) > 1 ? network + 1 : 0;
    }

    /*
     * Creates the maximum address in the network to which the address belongs.
     *
     * inclusiveHostCount
     *  - true: the broadcast address
     *  - false: the last address of the available as host addresses or 0 if no corresponding address
     */
    private int high() {
        return inclusiveHostCount ? broadcast : (broadcastLong() - networkLong()) > 1 ? broadcast - 1 : 0;
    }

    /**
     * Converts a 4-element array into dotted decimal format.
     */
    private static String format(final int[] octets) {
        final int last = octets.length - 1;
        final StringBuilder builder = new StringBuilder();
        for (int i = 0;; i++) {
            builder.append(octets[i]);
            if (i == last) {
                return builder.toString();
            }
            builder.append('.');
        }
    }

    /**
     * Converts a packed integer address into a 4-element array
     */
    private static int[] toArray4(final int val) {
        final int[] ret = new int[4];
        for (int j = 3; j >= 0; --j) {
            ret[j] |= val >>> 8 * (3 - j) & 0xff;
        }
        return ret;
    }

    /*
     * Converts a dotted decimal format address to a packed integer format.
     */
    private int toInteger(String address) {
        final String[] addrArry = address.split("\\.");

        // Check the length of the array, must be 4
        if (addrArry.length != 4) {
            throw new IllegalArgumentException("Could not parse [" + address + "]");
        }

        /* Check range of each element and convert to integer */
        int addr = 0;
        for (int i = 0; i < 4; i++) {
            final int n = rangeCheck(Integer.parseInt(addrArry[i]), 0, 255);
            addr |= (n & 0xff) << (8 * (3 - i));
        }

        return addr;
    }

    /**
     * Converts a dotted decimal format address to a packed integer format.
     *
     * @param address a dotted decimal format address
     * @return a packed integer of a dotted decimal format address
     */
    public int asInteger(String address) {
        return toInteger(address);
    }

    /**
     * Returns {@code true} if the parameter {@code address} is in the range of usable endpoint addresses for this subnet.
     * This excludes the network and broadcast addresses if {@code inclusiveHostCount} is {@code false}.
     *
     * @param address a dot-delimited IPv4 address, e.g. "192.168.0.1"
     * @return {@code true} if in range, {@code false} otherwise
     */
    @Override
    public boolean isInRange(String address) {
        return isInRange(toInteger(address));
    }

    /**
     * Returns {@code true} if the parameter {@code address} is in the range of usable endpoint addresses for this subnet.
     * This excludes the network and broadcast addresses if {@code inclusiveHostCount} is {@code false}.
     *
     * @param address an IPv4 address in binary
     * @return {@code true} if in range, {@code false} otherwise
     */
    @Override
    public boolean isInRange(int address) {
        final long addLong = address & UNSIGNED_INT_MASK;

        long low = 0;
        long high = 0;
        if (inclusiveHostCount) {
            low = networkLong();
            high = broadcastLong();
        } else {
            low = networkLong() + 1;
            high = broadcastLong() - 1;
        }

        return addLong >= low && addLong <= high;
    }

    @Override
    public Iterable<String> iterableAddressStrings() {
        return new SubnetAddressStringIterable(this);
    }

    @Override
    public Stream<String> streamAddressStrings() {
        return StreamSupport.stream(iterableAddressStrings().spliterator(), false);
    }

    /**
     * Returns the IPv4 address in the dotted decimal format, e.g. "192.168.0.1".
     *
     * @return a string of the IP address
     */
    @Override
    public String getAddress() {
        return format(toArray4(address));
    }

    /**
     * Returns the CIDR suffixes, the count of consecutive 1 bits in the subnet mask in range of 0-32.
     *
     * @return the CIDR suffixes of the address in an integer.
     */
    @Override
    public int getCIDR() {
        return cidr;
    }

    @Override
    public String getNetmask() {
        return format(toArray4(netmask));
    }

    @Override
    public String getNetworkAddress() {
        return format(toArray4(network));
    }

    @Override
    public String getNextAddress() {
        return format(toArray4(address + 1));
    }

    @Override
    public String getPreviousAddress() {
        return format(toArray4(address - 1));
    }

    @Override
    public String getBroadcastAddress() {
        return format(toArray4(broadcast));
    }

    /**
     * Returns a CIDR notation, in which the address is followed by slash and
     * the count of counting the 1-bit population in the subnet mask, e.g. "192.168.0.1/24".
     *
     * @return the CIDR notation of an IPv4 address
     */
    @Override
    public String getCIDRNotation() {
        return format(toArray4(address)) + "/" + cidr;
    }

    /**
     * Returns the lowest address as a dotted decimal IPv4 address.
     * Will be zero for CIDR/31 and CIDR/32 if the {@code inclusiveHostCount} flag is {@code false}.
     *
     * @return the IP address in the dotted decimal format, may be "0.0.0.0" if there is no valid address
     */
    @Override
    public String getLowAddress() {
        return format(toArray4(low()));
    }

    /**
     * Returns the highest address as a dotted decimal IPv4 address.
     * Will be zero for CIDR/31 and CIDR/32 if the {@code inclusiveHostCount} flag is {@code false}.
     *
     * @return the IP address in dotted decimal format, may be "0.0.0.0" if there is no valid address
     */
    @Override
    public String getHighAddress() {
        return format(toArray4(high()));
    }

    /**
     * Returns the count of available addresses.
     * Will be zero for CIDR/31 and CIDR/32 if the {@code inclusiveHostCount} flag is {@code false}.
     *
     * @return the count of addresses in a string, may be zero
     */
    @Override
    public BigInteger getAddressCountBigInteger() {
        return BigInteger.valueOf(getAddressCountLong());
    }

    /**
     * Returns the count of available addresses.
     * Will be zero for CIDR/31 and CIDR/32 if the {@code inclusiveHostCount} flag is {@code false}.
     *
     * @return the count of addresses, may be zero
     */
    @Override
    public long getAddressCountLong() {
        final long b = broadcastLong();
        final long n = networkLong();
        final long count = (b - n) + (inclusiveHostCount ? 1 : -1);
        return count < 0 ? 0 : count;
    }

    /**
     * Returns a list of the available addresses.
     *
     * @return an array of the available addresses
     */
    @Override
    public String[] getAllAddresses() {
        final int ct = getAddressCount();
        final String[] addresses = new String[ct];
        if (ct == 0) {
            return addresses;
        }
        for (int add = low(), j = 0; add <= high(); ++add, ++j) {
            addresses[j] = format(toArray4(add));
        }
        return addresses;
    }

    /**
     * Returns subnet summary information of the address,
     * which includes an IP address by CIDR-Notation with the netmask,
     * network address, broadcast address, the first and last addresses of the network,
     * and the number of available addresses in the network which includes
     * the network and broadcast addresses if the {@code inclusiveHostCount} flag is {@code true}.
     */
    @Override
    public String toString() {
        final StringBuilder buf = new StringBuilder();
        buf.append("CIDR-Notation:\t[").append(getCIDRNotation()).append("]")
                .append(" Netmask: [").append(getNetmask()).append("]\n")
                .append("Network:\t[").append(getNetworkAddress()).append("]\n")
                .append("Broadcast:\t[").append(getBroadcastAddress()).append("]\n")
                .append("First Address:\t[").append(getLowAddress()).append("]\n")
                .append("Last Address:\t[").append(getHighAddress()).append("]\n")
                .append("# Addresses:\t[").append(getAddressCountLong()).append("]\n");

        return buf.toString();
    }
}
