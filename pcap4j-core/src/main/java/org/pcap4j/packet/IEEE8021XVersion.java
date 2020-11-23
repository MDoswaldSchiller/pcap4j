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
package org.pcap4j.packet;

/**
 *
 * @author mdo
 */
public enum IEEE8021XVersion
{
  INVALID(0),
  IEEE802_1X_2001(1),
  IEEE802_1X_2004(2),
  IEEE802_1X_2010(3);
    
  private final int value;

  private IEEE8021XVersion(int value) {
    this.value = value;
  }

  /**
   * @param value value
   * @return a GtpVersion object.
   */
  public static IEEE8021XVersion getInstance(int value) {
    for (IEEE8021XVersion ver : values()) {
      if (ver.value == value) {
        return ver;
      }
    }
    throw new IllegalArgumentException("Invalid value: " + value);
  }

  /** @return value */
  public int getValue() {
    return value;
  }
}
