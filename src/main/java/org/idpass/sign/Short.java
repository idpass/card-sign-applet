package org.idpass.sign;

public class Short
{
    private final short value;

    public Short(short value)
    {
        this.value = value;
    }

    public short shortValue()
    {
        return value;
    }

    public byte byteValue()
    {
        return (byte)value;
    }
}
