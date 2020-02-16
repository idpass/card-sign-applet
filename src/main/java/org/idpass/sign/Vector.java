package org.idpass.sign;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import org.idpass.sign.Enumeration;

public class Vector
{
    protected Object[] elementData;
    protected short elementCount;
    protected short capacityIncrement;

    public Vector()
    {
        this((short)10, (short)0);
    }

    public Vector(short initialCapacity, short capacityIncrement)
    {
        if (initialCapacity < 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        elementData = new Object[initialCapacity];
        this.capacityIncrement = capacityIncrement;
    }

    public void addElement(Object obj)
    {
        if (elementCount == elementData.length) {
            ensureCapacity((short)(elementCount + 1));
        }
        elementData[elementCount++] = obj;
    }

    private short max(short a, short b)
    {
        return a > b ? a : b;
    }

    public void ensureCapacity(short minCapacity)
    {
        if (elementData.length >= minCapacity) {
            return;
        }

        short newCapacity;
        if (capacityIncrement <= 0) {
            newCapacity = (short)(elementData.length * 2);
        } else {
            newCapacity = (short)(elementData.length + capacityIncrement);
        }

        Object[] newArray
            = (Object[]) new Object[max(newCapacity, minCapacity)];

        for (short i = 0; i < elementData.length; i++) {
            newArray[i] = elementData[i];
        }

        elementData = newArray;
    }

    public Enumeration elements()
    {
        return new Enumeration() {
            private short i = 0;

            public boolean hasMoreElements()
            {
                return i < elementCount;
            }

            public Object nextElement()
            {
                if (i >= elementCount) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
                return (Object)elementData[i++];
            }
        };
    }

    public short size()
    {
        return elementCount;
    }
}
