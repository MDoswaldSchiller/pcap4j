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
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.EAPCode;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

/**
 *
 * @author mdo
 */
public class EAPPacket extends AbstractPacket
{
  private static final long serialVersionUID = 0L;
  
  private final EAPPacket.EAPPacketHeader header;
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
  public static EAPPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new EAPPacket(rawData, offset, length);
  }  
  
  private EAPPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException 
  {
    this.header = new EAPPacket.EAPPacketHeader(rawData, offset, length);
    
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
//      GtpV1ExtensionHeaderType type = header.getNextExtensionHeaderType();
//      if (type != null && !type.equals(GtpV1ExtensionHeaderType.NO_MORE_EXTENSION_HEADERS)) {
//        this.payload =
//            PacketFactories.getFactory(Packet.class, GtpV1ExtensionHeaderType.class)
//                .newInstance(rawData, offset + header.length(), payloadLength, type);
//      } else {
        this.payload =
            PacketFactories.getFactory(Packet.class, NotApplicable.class)
                .newInstance(
                    rawData, offset + header.length(), payloadLength, NotApplicable.UNKNOWN);
//      }
    } 
    else {
      this.payload = null;
    }    
  }
  
  private EAPPacket(EAPPacket.Builder builder) {
    if (builder == null || builder.code == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(", builder.code: ")
          .append(builder != null ? builder.code : "null");
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new EAPPacket.EAPPacketHeader(builder, payload != null ? payload.length() : 0);
  }  

  @Override
  public EAPPacketHeader getHeader()
  {
    return header;
  }

  @Override
  public Packet getPayload()
  {
    return payload;
  }
  
  @Override
  public Builder getBuilder()
  {
    return new Builder(this);
  }  
  
  
  public static final class Builder extends AbstractBuilder implements LengthBuilder<EAPPacket> {

    private EAPCode code;
    private byte identifier;
    private short length;
    private boolean correctLengthAtBuild;
    private Packet.Builder payloadBuilder;
    
    /** */
    public Builder() {}

    /** @param packet packet */
    public Builder(EAPPacket packet) {
      this.code = packet.header.code;
      this.identifier = packet.header.identifier;
      this.length = packet.header.length;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param code code
     * @return this Builder object for method chaining.
     */
    public EAPPacket.Builder code(EAPCode code) {
      this.code = code;
      return this;
    }

    /**
     * @param identifier identifier
     * @return this Builder object for method chaining.
     */
    public EAPPacket.Builder identifier(byte identifier) {
      this.identifier = identifier;
      return this;
    }

    /**
     * @param length length
     * @return this Builder object for method chaining.
     */
    public EAPPacket.Builder length(short length) {
      this.length = length;
      return this;
    }
    
    @Override
    public LengthBuilder<EAPPacket> correctLengthAtBuild(boolean correctLengthAtBuild)
    {
      this.correctLengthAtBuild = correctLengthAtBuild;
      return this;
    }

    @Override
    public EAPPacket build()
    {
      return new EAPPacket(this);
    }
  }
  
  public static final class EAPPacketHeader extends AbstractHeader
  {
    private static final long serialVersionUID = 0L;
    
    private static final int FIRST_OCTET_OFFSET = 0;
    private static final int IDENTIFIER_OFFSET = 1;
    private static final int LENGTH_OFFSET = 2;
    private static final int LENGTH_SIZE = 2;
    private static final int HEADER_SIZE = LENGTH_OFFSET + LENGTH_SIZE;
    
    private EAPCode code;
    private byte identifier;
    private short length;
    
    private EAPPacketHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException
    { 
      if (length < HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build a EAP header(")
            .append(HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }
    
      this.code = EAPCode.getInstance(ByteArrays.getByte(rawData, FIRST_OCTET_OFFSET+offset));
      this.identifier = ByteArrays.getByte(rawData, IDENTIFIER_OFFSET+offset);
      this.length = ByteArrays.getShort(rawData, LENGTH_OFFSET + offset);
    }
    
    private EAPPacketHeader(Builder builder, int payloadLen) 
    {
      this.code = builder.code;
      this.identifier = builder.identifier;
      
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
    
    public EAPCode getCode()
    {
      return code;
    }
    
    public byte getIdentifier()
    {
      return identifier;
    }
    
    @Override
    protected List<byte[]> getRawFields()
    {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray((byte)code.value()));
      rawFields.add(ByteArrays.toByteArray(identifier));
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
      sb.append("  Code: ").append(code).append(ls);
      sb.append("  Identifier: ").append(identifier).append(ls);
      sb.append("  Length: ").append(length).append(ls);

      return sb.toString();
    }    
  }
}
