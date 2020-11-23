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
public final class EAPCode extends NamedNumber<Byte, EAPCode>
{
  /** */
  private static final long serialVersionUID = 0L;

  private static final Map<Byte, EAPCode> registry = new HashMap<Byte, EAPCode>();
  
  public static final EAPCode REQUEST = new EAPCode((byte)1, "Request");
  
  public static final EAPCode RESPONSE = new EAPCode((byte)2, "Response");
  
  public static final EAPCode SUCCESS = new EAPCode((byte)3, "Success");
  
  public static final EAPCode FAILURE = new EAPCode((byte)4, "Failure");
    
  /**
   * @param value value
   * @param name name
   */
  public EAPCode(Byte value, String name) {
    super(value, name);
    registry.put(value, this);
  }

  /**
   * @param value value
   * @return a GtpV2MessageType object.
   */
  public static EAPCode getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new EAPCode(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a EtherType object.
   */
  public static EAPCode register(EAPCode type) {
    return registry.put(type.value(), type);
  }

  /** @return a string representation of this value. */
  @Override
  public String valueAsString() {
    return "0x" + ByteArrays.toHexString(value(), "");
  }

  @Override
  public int compareTo(EAPCode o) {
    return value().compareTo(o.value());
  }
}
