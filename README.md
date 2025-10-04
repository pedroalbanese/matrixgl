# Matrix-Based Cryptography (PoC)

This article presents a description of the Schnorr digital signature scheme and the ElGamal cryptographic protocol implemented over the general linear group GL(16, $\mathbb{F}\_{251}$) of invertible 16×16 matrices over the finite field $\mathbb{F}\_{251}$. This scheme represents a promising candidate for post-quantum cryptography as it relies on mathematical problems believed to be resistant to quantum attacks, particularly the Generalized Symmetric Decomposition Problem (GSDP) in non-abelian matrix groups.

## Mathematical Foundations

### General Linear Group GL(n, $\mathbb{F}_p$)

The general linear group GL(n, $\mathbb{F}_p$) consists of all invertible n×n matrices over the finite field $\mathbb{F}_p$, where $p$ is prime. The order of this group is given by:

$$|\mathrm{GL}(n, \mathbb{F}_p)| = \prod_{i=0}^{n-1}(p^n - p^i)$$

For n = 16 and p = 251:

$$|\mathrm{GL}(16, \mathbb{F}_{251})| = \prod_{i=0}^{15}(251^{16} - 251^i) \approx 2^{2041} \approx 10^{614.31}$$

This value significantly exceeds the order of groups used in traditional elliptic curve cryptography ($\approx 2^{256} \approx 10^{77}$), providing an extensive key space.

## Construction of the Generator Matrix $G$

Let $f(x) \in \mathbb{F}_{251}[x]$ be a monic irreducible polynomial of degree 16:

$$f(x) = x^{16} + a_{15}x^{15} + \cdots + a_1 x + a_0$$

Its companion matrix $C_f \in \mathrm{GL}(16, \mathbb{F}_{251})$ is:

$$C_f = 
\begin{bmatrix}
0 & 0 & \cdots & 0 & -a_0 \\
1 & 0 & \cdots & 0 & -a_1 \\
0 & 1 & \cdots & 0 & -a_2 \\
\vdots & \vdots & \ddots & \vdots & \vdots \\
0 & 0 & \cdots & 1 & -a_{15}
\end{bmatrix}$$

To hide this structure, the generator matrix $G$ is constructed by conjugation with a random invertible matrix $P \in \mathrm{GL}(16, \mathbb{F}_{251})$:

$$G = P C_f P^{-1}$$

This conjugation yields a matrix that has the same order as $C_f$ but no longer appears commutative or structured, increasing the difficulty of attacks exploiting algebraic structure.

## Matrix Operations in GL(16, $\mathbb{F}_{251}$)

### Matrix Addition

Given two matrices $A, B \in \mathrm{GL}(16, \mathbb{F}_{251})$:

$$C_{i,j} = (A_{i,j} + B_{i,j}) \mod p$$

### Matrix Multiplication

Given two matrices $A, B \in \mathrm{GL}(16, \mathbb{F}_{251})$:

$$C_{i,j} = \left( \sum_{k=0}^{15} A_{i,k} \cdot B_{k,j} \right) \mod p$$

### Matrix Exponentiation

Given a matrix $G \in \mathrm{GL}(16, \mathbb{F}_{251})$ and exponent $x$:

$$Y = G^x \mod p$$

Implemented using the square-and-multiply algorithm for efficiency:

$$G^x = \prod_{i=0}^{n-1} G^{2^i \cdot x_i} \mod p$$

where $x_i$ are the bits of the exponent $x$.

### Matrix Inversion

Given an invertible matrix $M \in \mathrm{GL}(16, \mathbb{F}_{251})$:

$$M \cdot M^{-1} = I \mod p$$

Implemented using Gaussian-Jordan elimination with modular arithmetic.

### Determinant Calculation

For a matrix $M \in \mathrm{GL}(16, \mathbb{F}_{251})$:

$$\det(M) \mod p$$

Calculated using modular Gaussian elimination to ensure the matrix is invertible (determinant ≠ 0 mod 251).

## Setup

### Key Generation

1. Public construction of an invertible matrix $G$ as the conjugated companion matrix
2. Generation of a private key $x$ (256 bits = 32 bytes)
3. Computation of the public key $Y = G^x \mod p$

## Schnorr Signature Protocol over Matrices

### Signature Generation

Given message $M \in \mathrm{GL}(16, \mathbb{F}_{251})$ and private key $x$:

1. Generate random nonce $k \pmod{q}$ where $q = |\mathrm{GL}(16, \mathbb{F}_{251})|$
2. Compute commitment $R = G^k$ (matrix exponentiation)
3. Compute challenge $e = H(M \parallel R) \pmod{q}$
4. Compute response $s = k - x \cdot e \pmod{q}$
5. Signature is the pair $(R, s)$

### Signature Verification

Given message $M$, signature $(R, s)$, and public key $Y = G^x$:

1. Compute challenge $e = H(M \parallel R) \pmod{q}$
2. Verify: $R = G^s \cdot Y^e$ (matrix operations)
3. If equality holds, signature is valid

### Security Analysis

Under the Random Oracle Model and assuming hardness of GSDP in GL(16, $\mathbb{F}_{251}$):

**Correctness:**

$$G^s \cdot Y^e = G^{k - x e} \cdot G^{x e} = G^k = R$$

- **Existential Unforgeability:** Follows from the hardness of the Generalized Symmetric Decomposition Problem in matrix groups.
- **Non-repudiation:** The algebraic structure ensures only the private key holder can generate valid signatures.

## Matrix ElGamal Protocol

### Encryption

Given a message $M \in \mathrm{GL}(16, \mathbb{F}_{251})$:

1. Generate an ephemeral value $k$ (256 bits)
2. Compute $C_1 = G^k \mod p$
3. Compute $s = Y^k \mod p$
4. Compute $C_2 = M \cdot s \mod p$
5. The ciphertext is the pair $(C_1, C_2)$

### Decryption

Given the ciphertext $(C_1, C_2)$ and private key $x$:

1. Compute $s = C_1^x \mod p$
2. Compute the inverse $s^{-1}$ of $s$
3. Recover $M = C_2 \cdot s^{-1} \mod p$

### Security Analysis

The system's security relies on the difficulty of the Generalized Symmetric Decomposition Problem (GSDP) and its stronger variant, the Blind Generalized Symmetric Decomposition Problem (BGSDP), in the non-abelian group $GL(16, \mathbb{F}_{251})$.

#### Generalized Symmetric Decomposition Problem (GSDP)

The GSDP is formally defined as follows: given a non-abelian group $G$, a public element $X \in G$, and a private subgroup $H \leq G$, find elements $A, B \in Hbo$ such that:

$$X = A \cdot B \cdot A^{-1} \cdot B^{-1} \quad \text{(Commutator Form)}$$

or alternatively, for some public integers $m, n \in \mathbb{Z}$:

$$X = A^m \cdot B \cdot A^n \quad \text{(Exponent Form)}$$

Both forms represent generalizations of group-based decomposition problems, which are conjectured to be hard in sufficiently large non-commutative groups such as $GL(n, \mathbb{F}_p)$, especially for $n \geq 8$.

#### Blind Generalized Symmetric Decomposition Problem (BGSDP)

The Blind GSDP (BGSDP) strengthens this setting by restricting the public information further: the structure of the subgroup $H$, the elements $A, B$, and even the exponents $m, n$ are hidden. The adversary is given only a group element $X \in G$ and must infer a decomposition without any knowledge of the generators or their algebraic relations.

These problems remain difficult for known quantum algorithms because:

1. Shor's algorithm requires abelian groups
2. Matrix groups are non-abelian (non-commutative)
3. Grover's algorithm provides only quadratic speedup, maintaining 128-bit security for 256-bit keys

**Key Strength:**

1. Private key: 256 bits (resistant to quantum brute-force attacks)
2. Public key: 2048 bits (16×16 matrix in $\mathbb{F}_{251}$)
3. Key space: $\approx 2^{2041} \approx 10^{614}$ possibilities
4. Signature size: 512 bytes
5. Security level: 127-bit quantum security

## Zero-Knowledge Proof over Matrices

### Protocol Description

To prove knowledge of $x$ without revealing it, the prover performs the following steps:

1. Choose a random nonce $r \in \mathbb{Z}_q$
2. Compute the commitment $T = G^r \mod p$
3. Compute challenge $c = H(G \parallel T) \mod q$
4. Compute the response $z = r + c \cdot x \mod q$
5. Send the pair $(T, z)$ as the proof

### Verification

Given the commitment $T$, response $z$, and public key $Y$, the verifier computes the challenge $c = H(G \parallel T) \mod q$ and verifies whether $G^z = T \cdot Y^c \mod p$.

### Correctness

Assuming honest execution, the verification holds:

Since $z = r + c \cdot x$, then $G^z = G^r \cdot G^{c \cdot x} = T \cdot Y^c \mod p$, confirming the proof.

### Simulation (Zero-Knowledge Property)

A simulator can generate a valid proof without knowledge of $x$ by choosing random $c, z \in \mathbb{Z}_q$, and computing $T = G^z \cdot Y^{-c} \mod p$. The resulting transcript $(T, z)$ is computationally indistinguishable from a real proof.

### Soundness

If a malicious prover can generate valid proofs $(T, z_1)$ and $(T, z_2)$ for the same commitment but different challenges $c_1 \ne c_2$, then the secret key $x$ can be recovered as:

$z_1 = r + c_1 \cdot x$ and $z_2 = r + c_2 \cdot x$, hence $x = (z_1 - z_2) / (c_1 - c_2) \mod q$

### Security under Non-Commutativity

Due to the non-commutative nature of matrix exponentiation in $\mathrm{GL}(16, \mathbb{F}_{251})$, standard algebraic attacks are ineffective. In general, $G^a \cdot G^b \ne G^{a+b}$, making the underlying discrete logarithm problem resistant to classical and quantum algorithms.

Shor's algorithm does not apply in non-abelian settings, and Grover's algorithm yields only a quadratic speedup, preserving the effective 128-bit security level for 256-bit secrets.

This matrix-based ZKP provides a robust and post-quantum secure method for proving knowledge of a secret without disclosing it, while preserving soundness and zero-knowledge under standard cryptographic assumptions.

## Comparison with Traditional Schemes

| Parameter | Traditional ElGamal/Schnorr | Matrix-Based ElGamal/Schnorr |
|-----------|:---------------------------:|:----------------------------:|
| Group | Elliptic Curve | GL(16, $\mathbb{F}_{251}$) |
| Key size | 32 bytes | 32 bytes |
| Signature size | 64 bytes | 512 bytes |
| Quantum resistance | Vulnerable | Resistant |
| Group structure | Abelian | Non-abelian |

## Example

```go
package main

import (
	"fmt"
	"log"

	matrixcrypto "github.com/pedroalbanese/matrixgl"
)

func main() {
	fmt.Println("=== MATRIX CRYPTO LIBRARY DEMONSTRATION ===")

	mc := matrixcrypto.New()

	// [1] Key Generation
	fmt.Println("\n[1] Generating key pair...")
	keyPair, err := mc.GenerateKeyPair()
	if err != nil {
		log.Fatal("Error generating key pair:", err)
	}
	fmt.Println("    Key pair generated successfully")
	fmt.Printf("    Private key size: %d bytes\n", len(keyPair.PrivateKey.X))
	fmt.Printf("    Public key G size: %d bytes\n", len(keyPair.PublicKey.G))
	fmt.Printf("    Public key Y size: %d bytes\n", len(keyPair.PublicKey.Y))

	// [2] Encryption
	fmt.Println("\n[2] Encrypting random message...")
	message := mc.GenerateRandomMessage()
	fmt.Printf("    Original message hash: %s...\n", mc.MatrixToHex(message)[:32])

	ciphertext, err := mc.Encrypt(keyPair.PublicKey, message)
	if err != nil {
		log.Fatal("Error encrypting message:", err)
	}
	fmt.Println("    Message encrypted successfully")
	fmt.Printf("    Ciphertext C1 size: %d bytes\n", len(ciphertext.C1))
	fmt.Printf("    Ciphertext C2 size: %d bytes\n", len(ciphertext.C2))

	// [3] Decryption & Verification
	fmt.Println("\n[3] Decrypting message and verifying integrity...")
	decryptedMessage, err := mc.Decrypt(keyPair.PrivateKey, ciphertext)
	if err != nil {
		log.Fatal("Error decrypting message:", err)
	}

	encryptionOK := mc.MatrixToHex(message) == mc.MatrixToHex(decryptedMessage)
	fmt.Printf("    Decryption verification: %t\n", encryptionOK)
	fmt.Printf("    Decrypted message hash: %s...\n", mc.MatrixToHex(decryptedMessage)[:32])

	// [4] Digital Signatures
	fmt.Println("\n[4] Signing confidential data...")
	data := []byte("Confidential data to be signed digitally using matrix cryptography")
	fmt.Printf("    Data to sign: %s\n", string(data))
	fmt.Printf("    Data size: %d bytes\n", len(data))

	signature, err := mc.Sign(keyPair.PrivateKey, data)
	if err != nil {
		log.Fatal("Error signing data:", err)
	}
	fmt.Println("    Data signed successfully")
	fmt.Printf("    Signature size: %d bytes\n", len(signature))

	// [5] Signature Verification
	fmt.Println("\n[5] Verifying digital signature...")
	signatureOK, err := mc.Verify(keyPair.PublicKey, data, signature)
	if err != nil {
		log.Fatal("Error verifying signature:", err)
	}
	fmt.Printf("    Signature verification: %t\n", signatureOK)

	// [6] Additional Security Tests
	fmt.Println("\n[6] Running additional security tests...")

	// Test with wrong data (should fail)
	wrongData := []byte("Wrong data that should fail verification")
	wrongSignatureOK, _ := mc.Verify(keyPair.PublicKey, wrongData, signature)
	fmt.Printf("    Wrong data signature verification (should be false): %t\n", wrongSignatureOK)

	// [7] PEM Serialization
	fmt.Println("\n[7] Testing PEM serialization...")

	privPEM, err := mc.PrivateKeyToPEM(keyPair.PrivateKey)
	if err != nil {
		log.Fatal("Error serializing private key to PEM:", err)
	}

	pubPEM, err := mc.PublicKeyToPEM(keyPair.PublicKey)
	if err != nil {
		log.Fatal("Error serializing public key to PEM:", err)
	}

	fmt.Println("    PEM serialization successful")
	fmt.Printf("    Private PEM size: %d bytes\n", len(privPEM))
	fmt.Printf("    Public PEM size: %d bytes\n", len(pubPEM))

	// [8] Final Results
	fmt.Println("\n[8] FINAL RESULTS:")
	fmt.Printf("    Encryption/Decryption: %t\n", encryptionOK)
	fmt.Printf("    Digital Signature: %t\n", signatureOK)
	fmt.Printf("    Security Tests (wrong data check): %t\n", !wrongSignatureOK)

	if encryptionOK && signatureOK && !wrongSignatureOK {
		fmt.Println("\nALL TESTS PASSED SUCCESSFULLY")
		fmt.Println("Matrix cryptography library is working correctly.")
	} else {
		fmt.Println("\nSOME TESTS FAILED")
	}

	fmt.Println("\nIMPLEMENTATION DETAILS:")
	fmt.Println("    Library: Matrix GL(16, F251)")
	fmt.Println("    Private key space: 2^256 possible keys")
	fmt.Println("    Matrix operations: Over finite field F251")
}
```

Go Playground:
https://go.dev/play/p/vRY0S4Y_0ku

## Contribute
**Use issues for everything**
- You can help and get help by:
  - Reporting doubts and questions
- You can contribute by:
  - Reporting issues
  - Suggesting new features or enhancements
  - Improve/fix documentation

## License

This project is licensed under the ISC License.

#### Copyright (c) 2020-2025 Pedro F. Albanese - ALBANESE Research Lab.  
Todos os direitos de propriedade intelectual sobre este software pertencem ao autor, Pedro F. Albanese. Vide Lei 9.610/98, Art. 7º, inciso XII.
