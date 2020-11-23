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
package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.util.ByteArrays;

/**
 *
 * @author mdo
 */
public class IEEE8021Type extends NamedNumber<Byte, IEEE8021Type>
{
  /** */
  private static final long serialVersionUID = 0L;

  private static final Map<Byte, IEEE8021Type> registry = new HashMap<Byte, IEEE8021Type>();
  
  public static final IEEE8021Type EAP_PACKET = new IEEE8021Type((byte)0, "EAP-Packet");
  
  public static final IEEE8021Type EAPOL_START = new IEEE8021Type((byte)1, "EAPOL-Start");
  
  public static final IEEE8021Type EAPOL_LOGOFF = new IEEE8021Type((byte)2, "EAPOL-Logoff");
  
  public static final IEEE8021Type EAPOL_KEY = new IEEE8021Type((byte)3, "EAPOL-Key");
  
  public static final IEEE8021Type EAPOL_ASF_ALERT = new IEEE8021Type((byte)4, "EAPOL-Encapsulated-ASF-Alert");
  
  /**
   * @param value value
   * @param name name
   */
  public IEEE8021Type(Byte value, String name) {
    super(value, name);
    registry.put(value, this);
  }

  /**
   * @param value value
   * @return a GtpV2MessageType object.
   */
  public static IEEE8021Type getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new IEEE8021Type(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a EtherType object.
   */
  public static IEEE8021Type register(IEEE8021Type type) {
    return registry.put(type.value(), type);
  }

  /** @return a string representation of this value. */
  @Override
  public String valueAsString() {
    return "0x" + ByteArrays.toHexString(value(), "");
  }

  @Override
  public int compareTo(IEEE8021Type o) {
    return value().compareTo(o.value());
  }
}
