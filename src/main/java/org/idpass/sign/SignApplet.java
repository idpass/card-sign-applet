/*
 * Copyright (C) 2020 Newlogic Impact Lab Pte. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.idpass.sign;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;

import org.idpass.tools.IdpassApplet;
import org.idpass.tools.SIOAuthListener;
import org.idpass.tools.Utils;

import javacard.security.*;

public class SignApplet extends IdpassApplet implements SIOAuthListener
{
    protected static final byte INS_SIGN = (byte)0xC0;
    protected static final byte INS_ESTABLISH_SECRET = (byte)0xE5;
    protected static final short SC_SECRET_LENGTH = 32;

    // Get signer's public key
    protected static final byte INS_GET_PUBKEY = (byte)0xEC;
    private static final byte P1_GETPUBKEY = (byte)0x00;
    private static final byte P2_GETPUBKEY = (byte)0x00;

    protected static final byte INS_LOAD_KEYPAIR = (byte)0xD0;

    // cryptographic constants
    static final byte SECP256K1_FP[] = {
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, (byte)0xFF, (byte)0xFF,
        (byte)0xFC, (byte)0x2F};

    static final byte SECP256K1_A[] = {
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00};

    static final byte SECP256K1_B[] = {
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x07};

    static final byte SECP256K1_G[] = {
        (byte)0x04, (byte)0x79, (byte)0xBE, (byte)0x66, (byte)0x7E, (byte)0xF9,
        (byte)0xDC, (byte)0xBB, (byte)0xAC, (byte)0x55, (byte)0xA0, (byte)0x62,
        (byte)0x95, (byte)0xCE, (byte)0x87, (byte)0x0B, (byte)0x07, (byte)0x02,
        (byte)0x9B, (byte)0xFC, (byte)0xDB, (byte)0x2D, (byte)0xCE, (byte)0x28,
        (byte)0xD9, (byte)0x59, (byte)0xF2, (byte)0x81, (byte)0x5B, (byte)0x16,
        (byte)0xF8, (byte)0x17, (byte)0x98, (byte)0x48, (byte)0x3A, (byte)0xDA,
        (byte)0x77, (byte)0x26, (byte)0xA3, (byte)0xC4, (byte)0x65, (byte)0x5D,
        (byte)0xA4, (byte)0xFB, (byte)0xFC, (byte)0x0E, (byte)0x11, (byte)0x08,
        (byte)0xA8, (byte)0xFD, (byte)0x17, (byte)0xB4, (byte)0x48, (byte)0xA6,
        (byte)0x85, (byte)0x54, (byte)0x19, (byte)0x9C, (byte)0x47, (byte)0xD0,
        (byte)0x8F, (byte)0xFB, (byte)0x10, (byte)0xD4, (byte)0xB8};

    static final byte SECP256K1_R[] = {
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
        (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, (byte)0xBA, (byte)0xAE,
        (byte)0xDC, (byte)0xE6, (byte)0xAF, (byte)0x48, (byte)0xA0, (byte)0x3B,
        (byte)0xBF, (byte)0xD2, (byte)0x5E, (byte)0x8C, (byte)0xD0, (byte)0x36,
        (byte)0x41, (byte)0x41};

    protected static final short SECP256K1_KEY_SIZE = 256;
    protected static final byte SECP256K1_K = (byte)0x01;
    protected static final short SC_KEY_LENGTH = 256;
    protected static final short MAX_PUBKEYS = 5;

    // cryptographic primitives
    private KeyAgreement ka;
    private KeyPair kp;
    private ECPublicKey pubKey;
    private ECPrivateKey privKey;
    private Signature signer;

    private byte[] sharedSecret;
    private byte[] pubKeys;
    private short nKeys;

    private boolean[] authenticated;

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        SignApplet applet = new SignApplet(bArray, bOffset, bLength);

        // GP-compliant JavaCard applet registration
        applet.register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }

    // default secret for SIO
    private static final byte DEFAULT_SECRET = (byte)0x9E;

    // instance fields
    private byte secret;

    protected SignApplet(byte[] bArray, short bOffset, byte bLength)
    {
        short offset = bOffset;
        offset += (bArray[offset]); // skip aid
        offset++;
        offset += (bArray[offset]); // skip privileges
        offset++;

        // default params
        byte secret = DEFAULT_SECRET;

        // read params
        short lengthIn = bArray[offset];
        if (lengthIn != 0) {
            if (1 <= lengthIn) {
                secret = bArray[(short)(offset + 1)];
            }
        }

        this.secret = secret;

        ka = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        kp = new KeyPair(KeyPair.ALG_EC_FP, (short)SC_KEY_LENGTH);
        privKey = (ECPrivateKey)kp.getPrivate();
        pubKey = (ECPublicKey)kp.getPublic();

        setCurveParameters((ECKey)privKey);
        setCurveParameters((ECKey)pubKey);

        kp.genKeyPair();

        ka.init(privKey);
        signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        signer.init(privKey, Signature.MODE_SIGN);

        pubKeys = new byte[0];

        authenticated = JCSystem.makeTransientBooleanArray(
            (short)1, JCSystem.CLEAR_ON_RESET);

        sharedSecret = JCSystem.makeTransientByteArray(
            (short)(SC_SECRET_LENGTH * 2), JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Shareable interface standart call from JCOP
     */
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter)
    {
        if (secret != parameter)
            return null;

        return (SIOAuthListener)this;
    }

    public void onPersonaAdded(short personaIndex)
    {
    }

    public void onPersonaDeleted(short personaIndex)
    {
    }

    public void onPersonaAuthenticated(short personaIndex, short score)
    {
        if (personaIndex != (short)0xFFFF) {
            authenticated[0] = true;
        }
    }

    protected void processSelect()
    {
        if (!selectingApplet()) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        setIncomingAndReceiveUnwrap();

        byte[] buffer = getApduData();

        short wLen = pubKey.getW(buffer, (short)0);
        setOutgoingAndSendWrap(buffer, Utils.SHORT_00, wLen);
    }

    protected void processInternal(APDU apdu) throws ISOException
    {
        switch (this.ins) {
        case INS_GET_PUBKEY:
            checkClaIsInterindustry();
            processGetPubKey();
            break;
        case INS_SIGN:
            checkClaIsInterindustry();
            processSign();
            break;
        case INS_ESTABLISH_SECRET:
            checkClaIsInterindustry();
            processEstablishSecret();
            break;
        case INS_LOAD_KEYPAIR:
            checkClaIsInterindustry();
            processLoadKey();
            break;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private boolean addPubKey(byte[] key)
    {
        if (nKeys >= MAX_PUBKEYS) {
            // rotate
            return false;
        }

        byte[] newList = new byte[(short)(pubKeys.length + key.length)];

        Util.arrayCopyNonAtomic(
            pubKeys, (short)0, newList, (short)0, (short)(pubKeys.length));

        short n = Util.arrayCopyNonAtomic(
            key, (short)0, newList, (short)(nKeys * 64), (short)key.length);

        pubKeys = newList;
        nKeys++;

        return true;
    }

    private void processEstablishSecret()
    {
        short lc = setIncomingAndReceiveUnwrap();
        byte[] buffer = getApduData();
        byte[] pubkey = new byte[lc]; // lc is well-known 65

        short len = Util.arrayCopyNonAtomic(
            buffer, (short)0, pubkey, (short)0, (short)pubkey.length);

        // boolean flag = addPubKey(pubkey);

        len = ka.generateSecret(pubkey, (short)0, lc, sharedSecret, (short)0);
    }

    private void processSign()
    {
        if (authenticated[0] == false) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short lc = setIncomingAndReceiveUnwrap();
        byte[] buffer = getApduData();

        byte[] output = new byte[72];
        signer.init(privKey, Signature.MODE_SIGN);
        short siglen = signer.signPreComputedHash(
            buffer, (short)0, MessageDigest.LENGTH_SHA_256, output, (short)0);
        Util.arrayCopyNonAtomic(output, (short)0, buffer, (short)0, siglen);
        setOutgoingAndSendWrap(buffer, Utils.SHORT_00, siglen);
    }

    private void processGetPubKey()
    {
        if (p1 != P1_GETPUBKEY || p2 != P2_GETPUBKEY) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short lc = setIncomingAndReceiveUnwrap();
        byte[] buffer = getApduData();
        short wLen = pubKey.getW(buffer, (short)0);
        setOutgoingAndSendWrap(buffer, Utils.SHORT_00, (short)(wLen));
    }

    protected void setCurveParameters(ECKey key)
    {
        key.setA(SECP256K1_A, (short)0x00, (short)SECP256K1_A.length);
        key.setB(SECP256K1_B, (short)0x00, (short)SECP256K1_B.length);
        key.setFieldFP(SECP256K1_FP, (short)0x00, (short)SECP256K1_FP.length);
        key.setG(SECP256K1_G, (short)0x00, (short)SECP256K1_G.length);
        key.setR(SECP256K1_R, (short)0x00, (short)SECP256K1_R.length);
        key.setK(SECP256K1_K);
    }

    private void processLoadKey()
    {
        if (!(isCheckC_MAC() && isCheckC_DECRYPTION())) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short lc = setIncomingAndReceiveUnwrap();
        byte[] buffer = getApduData();

        short offset = 1;
        short len = buffer[0];
        privKey.setS(buffer, offset, len);
        offset = (short)(2 + len);
        len = buffer[(short)(len + 1)];
        pubKey.setW(buffer, offset, len);
    }
}
