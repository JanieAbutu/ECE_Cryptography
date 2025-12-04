# ECC Banking System – Architecture & Sequence Diagrams

Below are visual diagrams that describe the functioning and attack flows.

---

## 1. High-Level Architecture

```
+-------------------+         +-----------------------+
|   User Device     |         |     Bank Server       |
|-------------------|         |-----------------------|
| - Generates TX    |  --->   | - Verifies Signature  |
| - Signs via ECC   |         | - Processes Payment   |
+-------------------+         +-----------------------+
            ^                           |
            |                           v
            |                    +-------------+
            |                    | Audit Logs  |
            |                    +-------------+
```

---

## 2. Transaction Signing Flow (Sequence Diagram)

```
User              BankingApp                ECDSA Module            Server
 |                     |                         |                     |
 |  Create TX          |                         |                     |
 |-------------------->|                         |                     |
 |                     |   Hash(tx)              |                     |
 |                     |------------------------>|                     |
 |                     |                         |                     |
 |                     |   Sign(hash)            |                     |
 |                     |<------------------------|                     |
 |   TX + Signature    |                         |                     |
 |<--------------------|                         |                     |
 |                     | Send to server          |                     |
 |-------------------------------------------------------------------->|
 |                     |                         |   Verify(sig,tx)   |
 |                     |                         |<-------------------|
```

---

## 3. Replay Attack Diagram

```
Attacker                         Server
   |                                 |
   |-- (old signed TX) ------------->|
   |                                 |-- verifies: VALID signature
   |                                 |-- transaction executed again (fraud)
```

---

## 4. MITM Tampering Attack

```
User ---> TX ---> [ MITM Attacker Modifies TX ] ---> Server

Result: Signature no longer matches → verification FAILS
```

---

## 5. Signature Malleability

```
Original Signature: (r, s)
Malleable Variant: (r, n - s)
```

Server must reject both.

---

These diagrams can be exported as PNG if needed.
