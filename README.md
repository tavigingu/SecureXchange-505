SecureXchange
=============

A secure cryptographic transaction management system implemented in C++ using OpenSSL.

Overview
--------

SecureXchange is a robust cryptographic application that enables secure transactions between entities. It implements advanced cryptographic techniques including elliptic curve cryptography, ECDH key exchange, symmetric encryption with a custom AES mode, and RSA signatures to ensure secure and authenticated communication.

Features
--------

-   **Entity Key Generation**
    -   Generates 256-bit elliptic curve key pairs for each entity
    -   Stores private keys in encrypted PEM format
    -   Secures public keys with GMAC authenticity verification
    -   Generates 3072-bit RSA key pairs for digital signatures
-   **Secure Handshake Protocol**
    -   ECDH key exchange with public key authentication
    -   Custom symmetric key derivation process
    -   Secure session establishment between entities
-   **Custom Encryption: AES-256-FancyOFB**
    -   Modified Output Feedback Mode with custom tweaks
    -   XOR operation with inverted IV for enhanced security
    -   Secure byte stream generation for message encryption
-   **Transaction Signing and Verification**
    -   RSA-3072 signatures for all transactions
    -   Complete transaction integrity protection
-   **ASN.1 DER Encoding**
    -   Structured storage of cryptographic elements
    -   StandardiZed formatting for all security artifacts
-   **Comprehensive Logging System**
    -   Binary journal of all entity actions
    -   Timestamped activity recording for audit purposes

Technical Implementation
------------------------

### Key Management

-   **Elliptic Curve Keys**: Uses secp256k1 curve for entity key pairs
-   **Key Authentication**: GMAC tags generated with PBKDF2 + SHA3-256
-   **RSA Keys**: 3072-bit keys for transaction signing

### Symmetric Key Derivation

The symmetric key derivation process follows these steps:

1.  Apply SHA-256 to the ECDH shared secret x-coordinate
2.  Split the SHA-256 result into two 16-byte parts and XOR them (SymLeft)
3.  Apply PBKDF2 with SHA-384 to the y-coordinate to produce 48 bytes (SymRight)
4.  XOR the first 16 bytes of SymRight with SymLeft to create the final AES key
5.  Use the remaining bytes from SymRight as additional cryptographic material

### Custom AES-FancyOFB Mode

The AES-256-FancyOFB mode operates similarly to standard OFB mode but incorporates an additional XOR operation with the inverted IV to enhance security and diffusion properties.

### Data Structures

The application uses ASN.1 DER encoding for its data structures:

**PubKeyMAC**:

```
PubKeyMAC := SEQUENCE {
    PubKeyName: PrintableString
    MACKey: OCTET STRING
    MACValue: OCTET STRING
}
```

**SymElements**:

```
SymElements := SEQUENCE {
    SymElementsID: INTEGER
    SymKey: OCTET STRING
    IV: OCTET STRING
}
```

**Transaction**:

```
Transaction := SEQUENCE {
    TransactionID: INTEGER
    Subject: PrintableString
    SenderID: INTEGER
    ReceiverID: INTEGER
    SymElementsID: INTEGER
    EncryptedData: OCTET STRING
    TransactionSign: OCTET STRING
}
```

### Logging System

All entity actions are logged in a binary journal with the following format:

```
<date><time><entity><action>
```

Requirements
------------

-   C++11 compiler or later
-   OpenSSL library (1.1.1 or newer)
-   Windows environment (due to specific Windows API calls)

Usage
-----

1.  Include the necessary headers in your project
2.  Create Entity objects for participants
3.  Use the Communication class to establish secure connections
4.  Send encrypted and signed transactions between entities

Example
-------

cpp

```
#include "Communication.h"

int main() {
    // Create two entities
    Entity entityA(IDGenerator::generate(), "Bob");
    Entity entityB(IDGenerator::generate(), "Alice");

    // Establish secure communication
    Communication secure_comm(entityA, entityB);

    // Send a secure transaction
    secure_comm.__trust_me_bro_transaction__("Transfer 100 BTC", "Payment");

    return 0;
}
```

Security Considerations
-----------------------

This implementation focuses on demonstrating cryptographic concepts and should be reviewed for production use. Notable security aspects include:

-   All private keys are encrypted with password protection
-   Public keys are authenticated with GMAC tags
-   The custom OFB mode adds additional complexity against certain attacks
-   Full transaction integrity is ensured through RSA signatures
-   Secure key derivation prevents key recovery from intercepted messages



Acknowledgments
---------------

This project was developed as an academic implementation of advanced cryptographic concepts, focusing on secure transaction management between entities in a distributed system.
