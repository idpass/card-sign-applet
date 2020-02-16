package org.idpass.sign;

import javacard.framework.Util;

public class ByteArrayOutputStream
{
    private static final short DEFAULT_INITIAL_BUFFER_SIZE = 32;
    protected byte[] buf;
    protected short count;

    public ByteArrayOutputStream()
    {
        this(DEFAULT_INITIAL_BUFFER_SIZE);
    }

    public ByteArrayOutputStream(short size)
    {
        buf = new byte[size];
        count = 0;
    }

    public void write(byte oneByte)
    {
        resize((short)1);
        buf[count++] = (byte)oneByte;
    }

    private void resize(short add)
    {
        if ((short)(count + add) > buf.length) {
            short newlen = (short)(buf.length * 2);
            if ((short)(count + add) > newlen) {
                newlen = (short)(count + add);
            }
            byte[] newbuf = new byte[newlen];
            Util.arrayCopyNonAtomic(
                buf, (short)0, newbuf, (short)0, (short)count);
            buf = newbuf;
        }
    }

    public byte[] toByteArray()
    {
        byte[] ret = new byte[count];
        Util.arrayCopyNonAtomic(buf, (short)0, ret, (short)0, (short)count);
        return ret;
    }
}
