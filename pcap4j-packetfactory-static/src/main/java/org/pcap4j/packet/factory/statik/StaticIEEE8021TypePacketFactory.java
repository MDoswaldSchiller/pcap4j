/*
 * The MIT License
 *
 * Copyright 2020 mdo.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.EAPPacket;
import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IEEE8021Type;

/**
 *
 * @author mdo
 */
public class StaticIEEE8021TypePacketFactory extends AbstractStaticPacketFactory<IEEE8021Type> {

  private static final StaticIEEE8021TypePacketFactory INSTANCE = new StaticIEEE8021TypePacketFactory();

  private StaticIEEE8021TypePacketFactory() {
    instantiaters.put(
        IEEE8021Type.EAP_PACKET,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return EAPPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<EAPPacket> getTargetClass() {
            return EAPPacket.class;
          }
        });
  }

  /** @return the singleton instance of StaticEtherTypePacketFactory. */
  public static StaticIEEE8021TypePacketFactory getInstance() {
    return INSTANCE;
  }
}
