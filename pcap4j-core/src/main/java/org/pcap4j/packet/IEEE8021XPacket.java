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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.IEEE8021Type;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 *
 * @author mdo
 */
public class IEEE8021XPacket extends AbstractPacket
{
  private static final long serialVersionUID = 0L;
  
  private final IEEE8021XHeader header;
  private final Packet payload;
  
  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IEEE8021XPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IEEE8021XPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IEEE8021XPacket(rawData, offset, length);
  }  
  
  private IEEE8021XPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException 
  {
    this.header = new IEEE8021XHeader(rawData, offset, length);
    
    int remainingRawDataLength = length - header.length();
    int payloadLength = header.getLengthAsInt();

    if (payloadLength < 0) {
      throw new IllegalRawDataException(
          "The value of length field seems to be wrong: " + header.getLengthAsInt());
    }

    if (payloadLength > remainingRawDataLength) {
      payloadLength = remainingRawDataLength;
    }

    if (payloadLength != 0) { // payloadLength is positive.
      if (Objects.equals(header.packetType, IEEE8021Type.EAP_PACKET)) {
        this.payload = PacketFactories.getFactory(EAPPacket.class, IEEE8021Type.class)
                .newInstance(rawData, offset + header.length(), payloadLength, header.packetType);
      } else {
        this.payload =
            PacketFactories.getFactory(Packet.class, NotApplicable.class)
                .newInstance(
                    rawData, offset + header.length(), payloadLength, NotApplicable.UNKNOWN);
      }
    } 
    else {
      this.payload = null;
    }    
  }
  
  private IEEE8021XPacket(IEEE8021XPacket.Builder builder) {
    if (builder == null
        || builder.version == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(", builder.version: ")
          .append(builder != null ? builder.version : "null");
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new IEEE8021XPacket.IEEE8021XHeader(builder, payload != null ? payload.length() : 0);
  }  

  public IEEE8021XHeader getHeader()
  {
    return header;
  }
  
  public Packet getPayload()
  {
    return payload;
  }
  
  @Override
  public Builder getBuilder()
  {
    return new Builder(this);
  }
  
  public static final class Builder extends AbstractBuilder implements LengthBuilder<IEEE8021XPacket> {

    private IEEE8021XVersion version;
    private IEEE8021Type packetType;
    private short length;
    private boolean correctLengthAtBuild;
    private Packet.Builder payloadBuilder;
    
    /** */
    public Builder() {}

    /** @param packet packet */
    public Builder(IEEE8021XPacket packet) {
      this.version = packet.header.version;
      this.packetType = packet.header.packetType;
      this.length = packet.header.length;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param version version
     * @return this Builder object for method chaining.
     */
    public IEEE8021XPacket.Builder version(IEEE8021XVersion version) {
      this.version = version;
      return this;
    }

    /**
     * @param packetType packet type
     * @return this Builder object for method chaining.
     */
    public IEEE8021XPacket.Builder packetType(IEEE8021Type packetType) {
      this.packetType = packetType;
      return this;
    }

    /**
     * @param length length
     * @return this Builder object for method chaining.
     */
    public IEEE8021XPacket.Builder length(short length) {
      this.length = length;
      return this;
    }
    
    @Override
    public LengthBuilder<IEEE8021XPacket> correctLengthAtBuild(boolean correctLengthAtBuild)
    {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public IEEE8021XPacket build()
    {
      return new IEEE8021XPacket(this);
    }
  }
  
  
  public static final class IEEE8021XHeader extends AbstractHeader
  {
    private static final long serialVersionUID = 0L;
    
    private static final int FIRST_OCTET_OFFSET = 0;
    private static final int PACKET_TYPE_OFFSET = 1;
    private static final int LENGTH_OFFSET = 2;
    private static final int LENGTH_SIZE = 2;
    private static final int HEADER_SIZE = LENGTH_OFFSET + LENGTH_SIZE;
    
    private IEEE8021XVersion version;
    private IEEE8021Type packetType;
    private short length;
    
    private IEEE8021XHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException
    { 
      if (length < HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build a IEEE 802.1X header(")
            .append(HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }
    
      this.version = IEEE8021XVersion.getInstance(ByteArrays.getByte(rawData, FIRST_OCTET_OFFSET+offset));
      this.packetType = IEEE8021Type.getInstance(ByteArrays.getByte(rawData, PACKET_TYPE_OFFSET+offset));
      this.length = ByteArrays.getShort(rawData, LENGTH_OFFSET + offset);
    }

    private IEEE8021XHeader(IEEE8021XPacket.Builder builder, int payloadLen) 
    {
      this.version = builder.version;
      this.packetType = builder.packetType;
      
      if (builder.correctLengthAtBuild) {
        this.length = (short) payloadLen;
      } 
      else {
        this.length = builder.length;
      }
    }    
    
    
    /** @return length */
    public short getLength() {
      return length;
    }

    /** @return length */
    public int getLengthAsInt() {
      return 0xFFFF & length;
    }    
    
    @Override
    protected List<byte[]> getRawFields()
    {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray((byte)version.getValue()));
      rawFields.add(ByteArrays.toByteArray(packetType.value()));
      rawFields.add(ByteArrays.toByteArray(length));
      
      return rawFields;
    }

    @Override
    protected int calcLength()
    {
      return HEADER_SIZE;
    }

    @Override
    protected String buildString()
    {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[IEEE 802.1X Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Version: ").append(version).append(ls);
      sb.append("  PacketType: ").append(packetType).append(ls);
      sb.append("  Length: ").append(length).append(ls);

      return sb.toString();
    }

    @Override
    public int hashCode()
    {
      int hash = 7;
      hash = 89 * hash + Objects.hashCode(this.version);
      hash = 89 * hash + Objects.hashCode(this.packetType);
      hash = 89 * hash + this.length;
      return hash;
    }

    @Override
    public boolean equals(Object obj)
    {
      if (this == obj) {
        return true;
      }
      if (obj == null) {
        return false;
      }
      if (getClass() != obj.getClass()) {
        return false;
      }
      final IEEE8021XHeader other = (IEEE8021XHeader) obj;
      if (this.length != other.length) {
        return false;
      }
      if (this.version != other.version) {
        return false;
      }
      if (!Objects.equals(this.packetType, other.packetType)) {
        return false;
      }
      return true;
    }
  }
}
