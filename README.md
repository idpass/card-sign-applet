# SIGN Applet

### General SW List

SW | DESCRIPTION
-- | -- 
0x9000 | No error
0x6982 | SCP Security Level is too low
0x6B00 | Incorrect parameters (P1,P2)
0x6700 | Wrong DATA length

### sign package
**sign** package contains the applet for doing ECDSA digital signing.

The signing operation is allowed ONLY if persona is authenticated in auth applet until card reset (ATR) event.

AID | DESCRIPTION
-- | --
F769647061737304 | Package AID
F769647061737304010001 | Applet AID. Last 4 digits of the AID (*0001*) is the applet version   

#### Install Parameters
ORDER | LENGTH | DESCRIPTION
-- | -- | --
0 | 1 | Secret. <br>Parameter for Shareble Interface Objects authentication. <br><br>*0x9E* - default value

If install parameters are not set, default values will be used (*0x9E*)

#### APDU Commands

##### SELECT

Secure Channel Protocol minimum level: *no auth*

C-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
CLA | 1 | 0x00
INS | 1 | 0xA4
P1 | 1 | 0x04
P2 | 1 | 0x00
LC | 1 | Applet instance AID length
DATA | var | Applet instance AID

R-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
DATA | 65 | Applet ECDSA public key
SW | 2 | Status Word (see **General SW List** section)

##### Digital Signing
Signs the input data.

Secure Channel Protocol minimum level: *no auth*

C-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
CLA | 1 | 0x00
INS | 1 | 0xDC
P1 | 1 | 0x00
P2 | 1 | 0x00
LC | 1 or 3 | length of data to decrypt<br>Maximum 1960 bytes for NXP EMV P60 chip
DATA | var | data to decrypt

R-APDU:

DATA TYPE | LENGTH | VALUE
-- | -- | --
DATA | var | Decrypted data
SW | 2 | Status Word <br>0x6984 - Signature verification failed<br>0x6A85 - no open slots found (no authenticated persona)<br>See **General SW List** section for other SW

### Contributors

Contributions are welcome!

- Newlogic Impact Lab
- Dexter Aparicio
