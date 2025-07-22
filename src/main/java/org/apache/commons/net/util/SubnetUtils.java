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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * This class that performs some subnet calculations given IP address in CIDR-notation.
 * <p>For IPv4 address subnet, especially Classless Inter-Domain Routing (CIDR),
 * refer to <a href="https://tools.ietf.org/html/rfc4632">RFC4632</a>.</p>
 * <p>For IPv6 address subnet, refer to <a href="https://tools.ietf.org/html/rfc4291#section-2.3">
 * Section 2.3 of RFC 4291</a>.</p>
 *
 * @since 2.0
 */
public class SubnetUtils {
    private static final String IPV4_ADDRESS = "(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})";
    private static final String IPV4_SLASH_FORMAT = IPV4_ADDRESS + "/(\\d{1,2})"; // 0 -> 32
    private static final Pattern IPV4_ADDRESS_PATTERN = Pattern.compile(IPV4_ADDRESS);
    private static final Pattern IPV4_CIDR_PATTERN = Pattern.compile(IPV4_SLASH_FORMAT);

    private static final String IPV6_ADDRESS = "(([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|"
            + "([0-9a-f]{1,4}:){1,7}:|"
            + "([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|"
            + "([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|"
            + "([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|"
            + "([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|"
            + "([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|"
            + "[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|"
            + ":((:[0-9a-f]{1,4}){1,7}|:))";
    private static final String IPV6_SLASH_FORMAT = IPV6_ADDRESS + "/(\\d{1,3})"; // 0 -> 32
    private static final Pattern IPV6_ADDRESS_PATTERN = Pattern.compile(IPV6_ADDRESS);
    private static final Pattern IPV6_CIDR_PATTERN = Pattern.compile(IPV6_SLASH_FORMAT);

    private final SubnetInfo subnetInfo;

    /**
     * Constructor that creates subnet summary information based on the provided IPv4 or IPv6 address in CIDR-notation,
     * e.g. "192.168.0.1/16" or "2001:db8:0:0:0:ff00:42:8329/46"
     * <p>
     * NOTE: IPv6 address does NOT allow to omit consecutive sections of zeros in the current version.
     *
     * @param cidrNotation IPv4 or IPv6 address, e.g. "192.168.0.1/16" or "2001:db8:0:0:0:ff00:42:8329/46"
     * @throws IllegalArgumentException if the parameter is invalid,
     *                                  e.g. does not match either n.n.n.n/m where n = 1-3 decimal digits, m = 1-2 decimal digits in range 0-32; or
     *                                  n:n:n:n:n:n:n:n/m n = 1-4 hexadecimal digits, m = 1-3 decimal digits in range 0-128.
     */
    public SubnetUtils(String cidrNotation) {
        subnetInfo = getByCIDRNotation(cidrNotation);
    }

    /**
     * Constructor that creates subnet summary information based on the provided IPv4 or IPv6 address in CIDR-notation,
     * e.g. "192.168.0.116" or "2001:db8:0:0:0:ff00:42:8329/46"
     *
     * @param addr an IP address, e.g. "192.168.0.1"
     * @param cidr the CIDR prefix bit size
     */
    public SubnetUtils(String addr, int cidr) {
        Matcher matcher = IPV4_ADDRESS_PATTERN.matcher(addr);
        if (matcher.matches()) {
            subnetInfo = new IP4Subnet(addr, cidr);
            return;
        }
        matcher = IPV6_ADDRESS_PATTERN.matcher(addr);
        if (matcher.matches()) {
            subnetInfo = new IP6Subnet(addr, cidr);
            return;
        }

        throw new IllegalArgumentException("Could not parse [" + addr + "/" + cidr + "]");
    }

    /**
     * Constructor that creates IPv4 subnet summary information, given a dotted decimal address and mask.
     *
     * @param address an IP address, e.g. "192.168.0.1"
     * @param mask    a dotted decimal netmask e.g. "255.255.0.0"
     * @throws IllegalArgumentException if the address or mask is invalid,
     *   e.g. the address does not match n.n.n.n where n=1-3 decimal digits, or
     *   the mask does not match n.n.n.n which n={0, 128, 192, 224, 240, 248, 252, 254, 255} and after the 0-field,
     *   it is all zeros.
     */
    public SubnetUtils(String address, String mask) {
        subnetInfo = new IP4Subnet(address, mask);
    }

    /**
     * Returns {@code true} if the return value of {@link SubnetInfo#getAddressCountLong() getAddressCountLong}
     * includes the network and broadcast addresses.
     *
     * @return {@code true} if the host count includes the network and broadcast addresses
     * @since 2.2
     */
    public boolean isInclusiveHostCount() {
        return subnetInfo.isInclusiveHostCount();
    }

    /**
     * Set to {@code true} if you want the return value of {@link SubnetInfo#getAddressCountLong() getAddressCountLong}
     * to include the network and broadcast addresses.
     *
     * @param inclusiveHostCount {@code true} if network and broadcast addresses are to be included
     * @since 2.2
     */
    public void setInclusiveHostCount(boolean inclusiveHostCount) {
        subnetInfo.setInclusiveHostCount(inclusiveHostCount);
    }

    /**
     * Creates subnet summary information based on the provided IPv4 or IPv6 address in CIDR-notation,
     * e.g. "192.168.0.1/16" or "2001:db8:0:0:0:ff00:42:8329/46"
     * <p>
     * NOTE: IPv6 address does NOT allow to omit consecutive sections of zeros in the current version.
     *
     * @param cidrNotation IPv4 or IPv6 address
     * @return a {@link SubnetInfo SubnetInfo} object created from the IP address.
     * @since 3.7
     */
    private static SubnetInfo getByCIDRNotation(String cidrNotation) {
        Matcher matcher = IPV4_CIDR_PATTERN.matcher(cidrNotation);
        if (matcher.matches()) {
            final String[] addrAndCidr = cidrNotation.split("/");
            final String addrString = addrAndCidr[0];
            final int cidr = Integer.parseInt(addrAndCidr[1]);
            return new IP4Subnet(addrString, cidr);
        }
        matcher = IPV6_CIDR_PATTERN.matcher(cidrNotation);
        if (matcher.matches()) {
            final String[] addrAndCidr = cidrNotation.split("/");
            final String addrString = addrAndCidr[0];
            final int cidr = Integer.parseInt(addrAndCidr[1]);
            return new IP6Subnet(addrString, cidr);
        }

        throw new IllegalArgumentException("Could not parse [" + cidrNotation + "]");
    }

    /**
     * Convenience container for subnet summary information.
     */
    public abstract static class SubnetInfo {

        /**
         * default constructor
         */
        protected SubnetInfo() {
        }

        /*
         * Convenience function to check integer boundaries.
         * Checks if a value x is in the range [begin,end].
         * Returns x if it is in range, throws an exception otherwise.
         */
        static int rangeCheck(int value, int begin, int end) {
            if (value < begin || value > end) {
                throw new IllegalArgumentException("Value [" + value + "] not in range [" + begin + "," + end + "]");
            }

            return value;
        }

        /*
         * Count the number of 1-bits in a 32-bit integer using a divide-and-conquer strategy see Hacker's Delight section 5.1
         */
        static int pop(int x) {
            x = x - ((x >>> 1) & 0x55555555);
            x = (x & 0x33333333) + ((x >>> 2) & 0x33333333);
            x = (x + (x >>> 4)) & 0x0F0F0F0F;
            x = x + (x >>> 8);
            x = x + (x >>> 16);
            return x & 0x3F;
        }

        /**
         * Converts a dotted decimal format address to a packed integer format. (ONLY USE in IPv4)
         *
         * @param address a dotted decimal format address
         * @return a packed integer of a dotted decimal format address
         */
        public abstract int asInteger(String address);

        /**
         * Returns {@code true} if the return value of {@link #getAddressCountLong() getAddressCountLong}
         * includes the network and broadcast addresses. (ONLY USE in IPv4)
         *
         * @return {@code true} if the host count includes the network and broadcast addresses
         */
        public abstract boolean isInclusiveHostCount();

        /**
         * Sets to {@code true} if you want the return value of {@link #getAddressCountLong() getAddressCountLong}
         * to include the network and broadcast addresses. (ONLY USE in IPv4)
         *
         * @param inclusiveHostCount {@code true} if network and broadcast addresses are to be included
         */
        public abstract void setInclusiveHostCount(boolean inclusiveHostCount);

        /**
         * Returns {@code true} if the parameter {@code address} is in the range of usable endpoint addresses for this subnet.
         * This excludes the network and broadcast addresses if the address is IPv4 address.
         *
         * @param address a dot-delimited IPv4 address, e.g. "192.168.0.1", or
         *                a colon-hexadecimal IPv6 address, e.g. "2001:db8::ff00:42:8329"
         * @return {@code true} if in range, {@code false} otherwise
         */
        public abstract boolean isInRange(String address);

        /**
         * Returns {@code true} if the parameter {@code address} is in the range of usable endpoint addresses for this subnet.
         * This excludes the network and broadcast addresses if the address is IPv4 address.
         *
         * @param address the address to check
         * @return {@code true} if it is in range
         */
        public abstract boolean isInRange(int address);

        /**
         * Creates a new Iterable of address Strings.
         *
         * @return a new Iterable of address Strings
         * @see #getAllAddresses()
         * @see #streamAddressStrings()
         * @since 3.12.0
         */
        public abstract Iterable<String> iterableAddressStrings();

        /**
         * Creates a new Stream of address Strings.
         *
         * @return a new Stream of address Strings.
         * @see #getAllAddresses()
         * @see #iterableAddressStrings()
         * @since 3.12.0
         */
        public abstract Stream<String> streamAddressStrings();

        /**
         * Returns the IP address.
         * <ul style="list-style-type: none">
         * <li>IPv4 format: a dot-decimal format, e.g. "192.168.0.1"</li>
         * <li>IPv6 format: a colon-hexadecimal format, e.g. "2001:db8::ff00:42:8329"</li>
         * </ul>
         *
         * @return a string of the IP address
         */
        public abstract String getAddress();

        /**
         * Returns the CIDR suffixes, the count of consecutive 1 bits in the subnet mask.
         * The range in IPv4 is 0-32, and in IPv6 is 0-128, actually 64 or less.
         *
         * @return the CIDR suffixes of the address in an integer.
         */
        public abstract int getCIDR();

        /**
         * Returns a netmask in the address. (ONLY USE IPv4)
         *
         * @return a string of netmask in a dot-decimal format.
         */
        public abstract String getNetmask();

        /**
         * Returns a network address in the address. (ONLY USE IPv4)
         *
         * @return a string of a network address in a dot-decimal format.
         */
        public abstract String getNetworkAddress();

        /**
         * Gets the next address for this subnet.
         *
         * @return the next address for this subnet.
         */
        public abstract String getNextAddress();

        /**
         * Gets the previous address for this subnet.
         *
         * @return the previous address for this subnet.
         */
        public abstract String getPreviousAddress();

        /**
         * Returns a broadcast address in the address. (ONLY USE IPv4)
         *
         * @return a string of a broadcast address in a dot-decimal format.
         */
        public abstract String getBroadcastAddress();

        /**
         * Returns a CIDR notation, in which the address is followed by slash and
         * the count of counting the 1-bit population in the subnet mask.
         * <ul style="list-style-type: none">
         * <li>IPv4 format: a dot-decimal format, e.g. "192.168.0.1"</li>
         * <li>IPv6 format: a colon-hexadecimal format, e.g. "2001:db8::ff00:42:8329"</li>
         * </ul>
         *
         * @return the CIDR notation of the address
         */
        public abstract String getCIDRNotation();

        /**
         * Returns a CIDR notation, in which the address is followed by slash and
         * the count of counting the 1-bit population in the subnet mask.
         * <ul style="list-style-type: none">
         * <li>IPv4 format: a dot-decimal format, e.g. "192.168.0.1"</li>
         * <li>IPv6 format: a colon-hexadecimal format, e.g. "2001:db8::ff00:42:8329"</li>
         * </ul>
         *
         * @return the CIDR notation of the address
         */
        public String getCidrSignature() {
            return getCIDRNotation();
        }

        /**
         * Returns the lowest address as a dotted decimal or the colon-separated hexadecimal IP address.
         * Will be zero for CIDR/31 and CIDR/32 if the address is IPv4 address and the {@code inclusiveHostCount} flag is {@code false}.
         *
         * @return the IP address in dotted or colon 16-bit delimited format, may be "0.0.0.0" or "::" if there is no valid address
         */
        public abstract String getLowAddress();

        /**
         * Returns the highest address as the dotted decimal or the colon-separated hexadecimal IP address.
         * Will be zero for CIDR/31 and CIDR/32 if the address is IPv4 address and the {@code inclusiveHostCount} flag is {@code false}.
         *
         * @return the IP address in dotted or colon 16-bit delimited format, may be "0.0.0.0" or "::" if there is no valid address
         */
        public abstract String getHighAddress();

        /**
         * Get the count of available addresses.
         * Will be zero for CIDR/31 and CIDR/32 if the {@code inclusiveHostCount} flag is {@code false}.
         *
         * @return the count of addresses, may be zero.
         * @throws RuntimeException if the correct count is greater than {@code Integer.MAX_VALUE}
         * @deprecated (3.4) use {@link #getAddressCountLong()} instead
         */
        @Deprecated
        public int getAddressCount() {
            final long countLong = getAddressCountLong();
            if (countLong > Integer.MAX_VALUE) {
                throw new RuntimeException("Count is larger than an integer: " + countLong);
            }
            // N.B. cannot be negative
            return (int) countLong;
        }

        /**
         * Returns the count of available addresses.
         * Will be zero for CIDR/31 and CIDR/32 if the address is IPv4 address and the {@code inclusiveHostCount} flag is {@code false}.
         *
         * @return the count of addresses, may be zero
         * @since 3.4
         */
        public abstract long getAddressCountLong();

        /**
         * Returns the count of available addresses.
         * Will be zero for CIDR/31 and CIDR/32 if the address is IPv4 address and the {@code inclusiveHostCount} flag is {@code false}.
         *
         * @return the count of addresses in a string, may be zero
         */
        public abstract BigInteger getAddressCountBigInteger();

        /**
         * Returns a list of the available addresses.
         *
         * @return an array of the available addresses
         */
        public abstract String[] getAllAddresses();

    }

    /**
     * Return a {@link SubnetInfo SubnetInfo} instance that contains subnet-specific statistics
     *
     * @return new instance
     */
    public final SubnetInfo getInfo() {
        return subnetInfo;
    }

    /**
     * Gets the next subnet for this instance.
     *
     * @return the next subnet for this instance.
     */
    public SubnetUtils getNext() {
        return new SubnetUtils(getInfo().getNextAddress(), getInfo().getCIDR());
    }

    /**
     * Gets the previous subnet for this instance.
     *
     * @return the next previous for this instance.
     */
    public SubnetUtils getPrevious() {
        return new SubnetUtils(getInfo().getPreviousAddress(), getInfo().getCIDR());
    }
}