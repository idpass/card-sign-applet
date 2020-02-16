package org.idpass.sign;

public interface Enumeration {
    /**
     * Tests whether there are elements remaining in the enumeration.
     *
     * @return true if there is at least one more element in the enumeration,
     *         that is, if the next call to nextElement will not throw a
     *         NoSuchElementException.
     */
    boolean hasMoreElements();

    /**
     * Obtain the next element in the enumeration.
     *
     * @return the next element in the enumeration
     * @throws NoSuchElementException if there are no more elements
     */
    Object nextElement();
}
