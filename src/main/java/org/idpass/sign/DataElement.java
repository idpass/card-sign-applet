package org.idpass.sign;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class DataElement
{
    public static final short NULL = 0x0000;
    public static final short INT_1 = 0x0010;
    public static final short INT_2 = 0x0011;
    public static final short DATSEQ = 0x0030;
    public static final short DATALT = 0x0038;
    public static final short PRIVATEKEY = 0x0039;
    public static final short PUBLICKEY = 0x003A;
    public static final short SIGNATURE_D = 0x003B;
    public static final short SIGNATURE_H = 0x003C;

    static byte[] validHeaders = {
        (byte)0x00, (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, (byte)0x0C,
        (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13, (byte)0x14, (byte)0x19,
        (byte)0x1A, (byte)0x1C, (byte)0x25, (byte)0x26, (byte)0x28, (byte)0x35,
        (byte)0x36, (byte)0x3D, (byte)0x3E, (byte)0x45, (byte)0x46, (byte)0x4D,
        (byte)0x55, (byte)0x5D, (byte)0x65};

    public static final byte TYPEDESC_NULL = 0x00;
    public static final byte TYPEDESC_INT_1 = 0x02;
    public static final byte TYPEDESC_INT_2 = 0x02;
    public static final byte TYPEDESC_DATASEQ = 0x06;
    public static final byte TYPEDESC_DATALT = 0x07;
    public static final byte TYPEDESC_PRIVATEKEY = 0x09;
    public static final byte TYPEDESC_PUBLICKEY = 0x0A;
    public static final byte TYPEDESC_SIGNATURE_D = 0x0B;
    public static final byte TYPEDESC_SIGNATURE_H = 0x0C;

    private Object value;
    private short valueType;

    private static ByteArrayOutputStream out;

    public short getShort()
    {
        switch (valueType) {
        case INT_1:
        case INT_2:
            return ((Short)value).shortValue();
        default:
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        return 0;
    }

    private void writeElement(DataElement d)
    {
        switch (d.getDataType()) {
        case DataElement.NULL:
            write((short)(0 | 0));
            break;
        case DataElement.INT_1:
            write((short)(16 | 0));
            writeLong(d.getShort(), (short)1);
            break;
        case DataElement.INT_2:
            write((short)(16 | 1));
            writeLong(d.getShort(), (short)2);
            break;
        case DataElement.PRIVATEKEY: {
            byte[] b = (byte[])d.getValue();
            write((short)(72 | 5));
            writeLong((short)b.length, (short)1);
            writeBytes(b);
            break;
        }

        case DataElement.PUBLICKEY: {
            byte[] b = (byte[])d.getValue();
            write((short)(80 | 5));
            writeLong((short)b.length, (short)1);
            writeBytes(b);
            break;
        }

        case DataElement.SIGNATURE_D: {
            byte[] b = (byte[])d.getValue();
            write((short)(88 | 5));
            writeLong((short)b.length, (short)1);
            writeBytes(b);
            break;
        }

        case DataElement.SIGNATURE_H: {
            byte[] b = (byte[])d.getValue();
            write((short)(96 | 5));
            writeLong((short)b.length, (short)1);
            writeBytes(b);
            break;
        }

        case DataElement.DATSEQ: {
            short sizeDescriptor;
            short len = getLength(d);
            short lenSize;
            if (len < (0xff + 2)) {
                sizeDescriptor = 5;
                lenSize = 1;
            } else if (len < (short)(0xFFFF + 3)) {
                sizeDescriptor = 6;
                lenSize = 2;
            } else {
                sizeDescriptor = 7;
                lenSize = 4;
            }
            len -= (1 + lenSize);
            write((short)(48 | sizeDescriptor));
            writeLong(len, lenSize);

            for (Enumeration e = (Enumeration)d.getValue();
                 e.hasMoreElements();) {
                writeElement((DataElement)e.nextElement());
            }

            break;
        }
        case DataElement.DATALT: {
            short sizeDescriptor;
            short len = (short)(getLength(d) - 5);
            short lenSize;
            if (len < 0xff) {
                sizeDescriptor = 5;
                lenSize = 1;
            } else if (len < (short)0xFFFF) {
                sizeDescriptor = 6;
                lenSize = 2;
            } else {
                sizeDescriptor = 7;
                lenSize = 4;
            }
            write((short)(56 | sizeDescriptor));
            writeLong(len, lenSize);

            for (Enumeration e = (Enumeration)d.getValue();
                 e.hasMoreElements();) {
                writeElement((DataElement)e.nextElement());
            }

            break;
        }

        default:
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    private void writeBytes(byte[] b)
    {
        for (short i = 0; i < b.length; i++) {
            write(b[i]);
        }
    }

    public void write(short oneByte)
    {
        out.write((byte)oneByte);
    }

    private void writeLong(short l, short size)
    {
        for (short i = 0; i < size; i++) {
            write((short)(l >> (size - 1 << 3)));
            l <<= 8;
        }
    }

    static short getLength(DataElement d)
    {
        switch (d.getDataType()) {
        case DataElement.NULL:
            return 1;

        case DataElement.INT_1:
            return 2;

        case DataElement.INT_2:
            return 3;

        case DataElement.PRIVATEKEY: {
            byte[] b = (byte[])d.getValue();
            return (short)(b.length + 2);
        }
        case DataElement.PUBLICKEY: {
            byte[] b = (byte[])d.getValue();
            return (short)(b.length + 2);
        }

        case DataElement.SIGNATURE_D: {
            byte[] b = (byte[])d.getValue();
            return (short)(b.length + 2);
        }

        case DataElement.SIGNATURE_H: {
            byte[] b = (byte[])d.getValue();
            return (short)(b.length + 2);
        }

        case DataElement.DATSEQ:
        case DataElement.DATALT: {
            short result = 1;

            for (Enumeration e = (Enumeration)d.getValue();
                 e.hasMoreElements();) {
                result += getLength((DataElement)e.nextElement());
            }
            if (result < 0xff) {
                result += 1;
            } else if (result < (short)0xFFFF) {
                result += 2;
            } else {
                result += 4;
            }

            return result;
        }

        default:
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        return 0;
    }

    public short getDataType()
    {
        return valueType;
    }

    public DataElement(short valueType)
    {
        switch (valueType) {
        case NULL:
            value = null;
            break;
        case DATALT:
        case DATSEQ:
            value = new Vector();
            break;
        default:
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        this.valueType = valueType;
    }

    public Object getValue()
    {
        switch (valueType) {
        case PRIVATEKEY:
        case PUBLICKEY:
        case SIGNATURE_D:
        case SIGNATURE_H: {
            // Modifying the returned Object will not change this DataElemen
            return clone((byte[])value);
        }
        case DATSEQ:
        case DATALT:
            return ((Vector)value).elements();
        default:
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        return null;
    }

    public DataElement(short valueType, short value)
    {
        switch (valueType) {
        case INT_1:
            if (value < -0x80 || value > 0x7f) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            break;
        case INT_2:
            if (value < -0x8000 || value > 0x7fff) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            break;
        default:
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        this.value = new Short(value);
        this.valueType = valueType;
    }

    public DataElement(short valueType, Object value)
    {
        if (value == null) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        switch (valueType) {
        case PRIVATEKEY:
            if (!(value instanceof byte[])) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            break;
        case PUBLICKEY:
            if (!(value instanceof byte[])) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            break;
        case SIGNATURE_D:
            if (!(value instanceof byte[])) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            break;
        case SIGNATURE_H:
            if (!(value instanceof byte[])) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            break;
        default:
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        this.value = value;
        this.valueType = valueType;
    }

    public void addElement(DataElement elem)
    {
        if (elem == null) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        switch (valueType) {
        case DATALT:
        case DATSEQ:
            ((Vector)value).addElement(elem);
            break;
        default:
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    public byte[] toByteArray()
    {
        switch (this.valueType) {
        case DATALT:
        case DATSEQ:
            out = new ByteArrayOutputStream();
            break;
        default:
            out = new ByteArrayOutputStream((short)4);
            break;
        }

        writeElement(this);
        return out.toByteArray();
    }

    private static byte[] clone(byte[] value)
    {
        if (value == null) {
            return null;
        }
        short length = (short)value.length;
        byte[] bClone = new byte[length];
        Util.arrayCopyNonAtomic(
            value, (short)0, bClone, (short)0, (short)length);
        return bClone;
    }

    protected static boolean validHeader(byte h)
    {
        for (short i = 0; i < validHeaders.length; i++) {
            if (validHeaders[i] == h) {
                return true;
            }
        }

        return false;
    }

    public static byte[] extract(byte[] deBuf, byte t)
    {
        byte[] result = {};
        short n;

        for (short i = 0; i < deBuf.length;) {
            byte header = deBuf[i];

            if (!DataElement.validHeader(header)) {
                return result;
            }

            byte typeDesc = (byte)(header >> 3);
            byte sizeDesc = (byte)(header & 0x07);

            switch (typeDesc) {
            case TYPEDESC_NULL:
                i++;
                break;
            case TYPEDESC_INT_1: // or TYPEDESC_INT_2
                switch (sizeDesc) {
                case 0: // 1 byte
                    i += 2;
                    break;
                case 1: // 2 bytes
                    i += 3;
                    break;
                }
                break;
            case TYPEDESC_DATASEQ:
            case TYPEDESC_DATALT:
                switch (sizeDesc) {
                case 5:
                    i += 2;
                    break;
                case 6:
                    i += 3;
                    break;
                }
                break;
            case TYPEDESC_PRIVATEKEY:
            case TYPEDESC_PUBLICKEY:
            case TYPEDESC_SIGNATURE_H:
            case TYPEDESC_SIGNATURE_D:
                i++;
                n = deBuf[i];
                i++;
                if (t == typeDesc) {
                    result = new byte[n];
                    for (short idx = 0; idx < result.length; idx++) {
                        result[idx] = deBuf[i];
                        i++;
                    }
                    return result;
                } else {
                    i += n;
                }
                break;
            }
        }

        return result;
    }
}
