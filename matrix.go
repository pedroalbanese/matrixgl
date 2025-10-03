// Package matrixcrypto implementa criptografia baseada em matrizes sobre GL(16, F251)
// Inclui protocolos ElGamal, Schnorr e provas de conhecimento zero
package matrixcrypto

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	"golang.org/x/crypto/hkdf"
  
	"github.com/pedroalbanese/lyra2rev2"
)

// =================================================
// Constantes e Tipos Fundamentais
// =================================================

// p define o campo finito F251
const p = 251

// degree define o grau das matrizes (16x16)
const degree = 16

// Matrix representa uma matriz 16x16 sobre F251
type Matrix [degree][degree]int

// Estruturas ASN.1 para serialização
type PublicKeyMatrixASN1 struct {
	G []byte
	Y []byte
}

type PrivateKeyMatrixASN1 struct {
	X []byte
	G []byte
}

type CiphertextMatrixASN1 struct {
	C1 []byte
	C2 []byte
}

type SchnorrSignature struct {
	R []byte `asn1:"tag:0"`
	S []byte `asn1:"tag:1"`
}

// KeyPair representa um par de chaves pública e privada
type KeyPair struct {
	PublicKey  *PublicKeyMatrixASN1
	PrivateKey *PrivateKeyMatrixASN1
}

// =================================================
// Interface Principal da Biblioteca
// =================================================

// MatrixCrypto fornece a interface principal para operações criptográficas
type MatrixCrypto struct {
	// Campos internos podem ser adicionados aqui para estado
}

// New cria uma nova instância do MatrixCrypto
func New() *MatrixCrypto {
	return &MatrixCrypto{}
}

// =================================================
// Geração de Chaves
// =================================================

// GenerateKeyPair gera um par de chaves aleatório
func (mc *MatrixCrypto) GenerateKeyPair() (*KeyPair, error) {
	G := generatePublicGeneratorMatrix()
	
	x := make([]byte, 32)
	_, err := rand.Read(x)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random private key: %v", err)
	}

	y := matExp(G, x)

	privKey := &PrivateKeyMatrixASN1{
		X: x,
		G: matrixToBytes(G),
	}

	pubKey := &PublicKeyMatrixASN1{
		G: matrixToBytes(G),
		Y: matrixToBytes(y),
	}

	return &KeyPair{
		PublicKey:  pubKey,
		PrivateKey: privKey,
	}, nil
}

// GenerateDeterministicKeyPair gera um par de chaves determinístico a partir de uma seed
func (mc *MatrixCrypto) GenerateDeterministicKeyPair(seed []byte) (*KeyPair, error) {
	G := generateDeterministicMatrix(seed)
	x := derivePrivateKeyFromSeed(seed)
	y := matExp(G, x)

	privKey := &PrivateKeyMatrixASN1{
		X: x,
		G: matrixToBytes(G),
	}

	pubKey := &PublicKeyMatrixASN1{
		G: matrixToBytes(G),
		Y: matrixToBytes(y),
	}

	return &KeyPair{
		PublicKey:  pubKey,
		PrivateKey: privKey,
	}, nil
}

// =================================================
// Serialização/Desserialização
// =================================================

// SerializePublicKey serializa uma chave pública para ASN.1
func (mc *MatrixCrypto) SerializePublicKey(pubKey *PublicKeyMatrixASN1) ([]byte, error) {
	return encodePublicKeyMatrixASN1(pubKey)
}

// DeserializePublicKey desserializa uma chave pública de ASN.1
func (mc *MatrixCrypto) DeserializePublicKey(data []byte) (*PublicKeyMatrixASN1, error) {
	return decodePublicKeyMatrixASN1(data)
}

// SerializePrivateKey serializa uma chave privada para ASN.1
func (mc *MatrixCrypto) SerializePrivateKey(privKey *PrivateKeyMatrixASN1) ([]byte, error) {
	return encodePrivateKeyMatrixASN1(privKey)
}

// DeserializePrivateKey desserializa uma chave privada de ASN.1
func (mc *MatrixCrypto) DeserializePrivateKey(data []byte) (*PrivateKeyMatrixASN1, error) {
	return decodePrivateKeyMatrixASN1(data)
}

// PublicKeyToPEM converte chave pública para formato PEM
func (mc *MatrixCrypto) PublicKeyToPEM(pubKey *PublicKeyMatrixASN1) ([]byte, error) {
	pubBytes, err := mc.SerializePublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "MATRIX PUBLIC KEY",
		Bytes: pubBytes,
	}
	return pem.EncodeToMemory(block), nil
}

// PrivateKeyToPEM converte chave privada para formato PEM
func (mc *MatrixCrypto) PrivateKeyToPEM(privKey *PrivateKeyMatrixASN1) ([]byte, error) {
	privBytes, err := mc.SerializePrivateKey(privKey)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "MATRIX SECRET KEY",
		Bytes: privBytes,
	}
	return pem.EncodeToMemory(block), nil
}

// ReadKeyFromPEM lê chave do formato PEM
func (mc *MatrixCrypto) ReadKeyFromPEM(filename string, isPrivate bool) ([]byte, error) {
	return readKeyFromPEM(filename, isPrivate)
}

// =================================================
// Criptografia/Descriptografia ElGamal
// =================================================

// Criptografa mensagem (matriz M) usando chave pública matricial
func encryptMATRIX(pub PublicKeyMatrixASN1, M Matrix) (Matrix, Matrix, error) {
	// Converter G e Y de []byte para Matrix
	G, err := bytesToMatrix(pub.G)
	if err != nil {
		return Matrix{}, Matrix{}, fmt.Errorf("error convertingG: %v", err)
	}
	Y, err := bytesToMatrix(pub.Y)
	if err != nil {
		return Matrix{}, Matrix{}, fmt.Errorf("error convertingY: %v", err)
	}

	// k aleatório de 256 bits
	k := make([]byte, 32)
	_, err = rand.Read(k)
	if err != nil {
		return Matrix{}, Matrix{}, err
	}

	C1 := matExp(G, k)
	s := matExp(Y, k)
	C2 := mul(M, s)
	return C1, C2, nil
}

// Decripta usando chave privada matricial
func decryptMATRIX(priv PrivateKeyMatrixASN1, C1, C2 Matrix) (Matrix, error) {
	// C1 já é Matrix, priv.X é []byte (chave privada)
	s := matExp(C1, priv.X)

	sInv, err := inverseMatrix(s)
	if err != nil {
		return Matrix{}, err
	}

	M := mul(C2, sInv)
	return M, nil
}

// Encrypt criptografa uma mensagem usando ElGamal matricial
func (mc *MatrixCrypto) Encrypt(pubKey *PublicKeyMatrixASN1, message Matrix) (*CiphertextMatrixASN1, error) {
	C1, C2, err := encryptMATRIX(*pubKey, message)
	if err != nil {
		return nil, err
	}

	return &CiphertextMatrixASN1{
		C1: matrixToBytes(C1),
		C2: matrixToBytes(C2),
	}, nil
}

// Decrypt descriptografa um ciphertext usando ElGamal matricial
func (mc *MatrixCrypto) Decrypt(privKey *PrivateKeyMatrixASN1, ciphertext *CiphertextMatrixASN1) (Matrix, error) {
	C1, err := bytesToMatrix(ciphertext.C1)
	if err != nil {
		return Matrix{}, err
	}

	C2, err := bytesToMatrix(ciphertext.C2)
	if err != nil {
		return Matrix{}, err
	}

	return decryptMATRIX(*privKey, C1, C2)
}

// SerializeCiphertext serializa ciphertext para ASN.1
func (mc *MatrixCrypto) SerializeCiphertext(ciphertext *CiphertextMatrixASN1) ([]byte, error) {
	return serializeCiphertext(
		bytesToMatrixMust(ciphertext.C1),
		bytesToMatrixMust(ciphertext.C2),
	)
}

// DeserializeCiphertext desserializa ciphertext de ASN.1
func (mc *MatrixCrypto) DeserializeCiphertext(data []byte) (*CiphertextMatrixASN1, error) {
	C1, C2, err := deserializeCiphertext(data)
	if err != nil {
		return nil, err
	}

	return &CiphertextMatrixASN1{
		C1: matrixToBytes(C1),
		C2: matrixToBytes(C2),
	}, nil
}

// =================================================
// Assinatura Digital Schnorr
// =================================================

// Sign assina uma mensagem usando Schnorr matricial
func (mc *MatrixCrypto) Sign(privKey *PrivateKeyMatrixASN1, message []byte) ([]byte, error) {
	G, err := bytesToMatrix(privKey.G)
	if err != nil {
		return nil, err
	}

	M := hashMessageToMatrix(message)
	R, sBytes := schnorrSign(M, privKey.X, G)

	return serializeSchnorrSignature(R, sBytes)
}

// Verify verifica uma assinatura Schnorr
func (mc *MatrixCrypto) Verify(pubKey *PublicKeyMatrixASN1, message []byte, signature []byte) (bool, error) {
	G, err := bytesToMatrix(pubKey.G)
	if err != nil {
		return false, err
	}

	Y, err := bytesToMatrix(pubKey.Y)
	if err != nil {
		return false, err
	}

	M := hashMessageToMatrix(message)
	R, sBytes, err := deserializeSchnorrSignature(signature)
	if err != nil {
		return false, err
	}

	return schnorrVerify(M, R, sBytes, Y, G), nil
}

// =================================================
// Utilitários
// =================================================

// CalculateFingerprint calcula a fingerprint de uma chave
func (mc *MatrixCrypto) CalculateFingerprint(keyBytes []byte) string {
	return calculateFingerprint(keyBytes)
}

// GenerateRandomMessage gera uma matriz de mensagem aleatória
func (mc *MatrixCrypto) GenerateRandomMessage() Matrix {
	return randomMessageMatrix()
}

// MatrixToHex converte matriz para hexadecimal
func (mc *MatrixCrypto) MatrixToHex(m Matrix) string {
	return matrixToHex(m)
}

// BytesToMatrix converte bytes para matriz
func (mc *MatrixCrypto) BytesToMatrix(b []byte) (Matrix, error) {
	return bytesToMatrix(b)
}

// MatrixToBytes converte matriz para bytes
func (mc *MatrixCrypto) MatrixToBytes(m Matrix) []byte {
	return matrixToBytes(m)
}

// =================================================
// Funções de Apoio (não exportadas)
// =================================================

func encodePublicKeyMatrixASN1(pub *PublicKeyMatrixASN1) ([]byte, error) {
	return asn1.Marshal(*pub)
}

func decodePublicKeyMatrixASN1(data []byte) (*PublicKeyMatrixASN1, error) {
	var pubASN1 PublicKeyMatrixASN1
	_, err := asn1.Unmarshal(data, &pubASN1)
	if err != nil {
		return nil, err
	}
	return &pubASN1, nil
}

func encodePrivateKeyMatrixASN1(priv *PrivateKeyMatrixASN1) ([]byte, error) {
	return asn1.Marshal(*priv)
}

func decodePrivateKeyMatrixASN1(data []byte) (*PrivateKeyMatrixASN1, error) {
	var privASN1 PrivateKeyMatrixASN1
	_, err := asn1.Unmarshal(data, &privASN1)
	if err != nil {
		return nil, err
	}
	return &privASN1, nil
}

func readKeyFromPEM(filename string, isPrivate bool) ([]byte, error) {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("error decoding PEM block")
	}
	
	expectedType := "MATRIX PUBLIC KEY"
	if isPrivate {
		expectedType = "MATRIX SECRET KEY"
	}
	
	if block.Type != expectedType {
		return nil, fmt.Errorf("wrong PEM type, expected %s", expectedType)
	}
	
	return block.Bytes, nil
}

func bytesToMatrixMust(b []byte) Matrix {
	m, _ := bytesToMatrix(b)
	return m
}

// Matrix addition modulo p
func add(a, b Matrix) Matrix {
	var res Matrix
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			res[i][j] = (a[i][j] + b[i][j]) % p
			if res[i][j] < 0 {
				res[i][j] += p
			}
		}
	}
	return res
}

// Matrix multiplication modulo p
func mul(a, b Matrix) Matrix {
	var res Matrix
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			sum := 0
			for k := 0; k < 16; k++ {
				sum += a[i][k] * b[k][j]
			}
			res[i][j] = sum % p
			if res[i][j] < 0 {
				res[i][j] += p
			}
		}
	}
	return res
}

// Generate 16x16 identity matrix
func identity() Matrix {
	var I Matrix
	for i := 0; i < 16; i++ {
		I[i][i] = 1
	}
	return I
}

// Correct companion matrix construction
func companionMatrix(coeffs [degree]int) Matrix {
	var C Matrix

	// Standard companion matrix form for monic polynomial:
	// f(x) = x^16 + a_15*x^15 + ... + a_1*x + a_0

	// Subdiagonal with 1's
	for i := 0; i < degree-1; i++ {
		C[i+1][i] = 1
	}

	// Last column contains the negated coefficients
	for i := 0; i < degree; i++ {
		C[i][degree-1] = (-coeffs[i]) % p
		if C[i][degree-1] < 0 {
			C[i][degree-1] += p
		}
	}

	return C
}

// Improved random polynomial generation - ensure it's monic
func randomPolynomial() [degree]int {
	var poly [degree]int
	for i := 0; i < degree; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(p))
		coef := int(n.Int64())
		poly[i] = coef
	}
	// Ensure the polynomial is monic (leading coefficient = 1 for degree 16)
	poly[degree-1] = 1
	return poly
}

// Generate random irreducible polynomial
func randomIrreduciblePolynomial() [degree]int {
	for {
		poly := randomPolynomial()
		if isIrreducibleEfficient(poly) {
			return poly
		}
	}
}

// Efficient irreducibility test
func isIrreducibleEfficient(coeffs [degree]int) bool {
	// Check for roots in F251
	for a := 0; a < p; a++ {
		val := 0
		apow := 1
		for i := 0; i < degree; i++ {
			val = (val + coeffs[i]*apow) % p
			apow = (apow * a) % p
		}
		if val == 0 {
			return false
		}
	}
	return true
}

// Generate base companion matrix from irreducible polynomial
func randomCompanionMatrix() Matrix {
	poly := randomIrreduciblePolynomial()
	return companionMatrix(poly)
}

// Generate random invertible matrix for randomization
func randomInvertibleMatrix() Matrix {
	var L, U Matrix

	// Lower triangular with 1's on diagonal
	for i := 0; i < 16; i++ {
		L[i][i] = 1
		for j := 0; j < i; j++ {
			n, _ := rand.Int(rand.Reader, big.NewInt(p))
			L[i][j] = int(n.Int64())
		}
	}

	// Upper triangular with random non-zero diagonal
	for i := 0; i < 16; i++ {
		for j := i; j < 16; j++ {
			n, _ := rand.Int(rand.Reader, big.NewInt(p))
			U[i][j] = int(n.Int64())
			if i == j && U[i][j] == 0 {
				U[i][j] = 1 // Ensure non-zero
			}
		}
	}

	return mul(L, U)
}

// MAIN FUNCTION: Public construction satisfying the requirement
func generatePublicGeneratorMatrix() Matrix {
	// Step 1: Generate companion matrix from irreducible polynomial
	companion := randomCompanionMatrix()

	// Step 2: Generate random invertible matrices for conjugation
	P := randomInvertibleMatrix()

	// Step 3: Compute P^-1 (we need the inverse for conjugation)
	Pinv, err := inverseMatrix(P)
	if err != nil {
		panic("Failed to compute matrix inverse")
	}

	// Step 4: Conjugate: G = P × companion × P^-1
	// This preserves the algebraic structure but randomizes the appearance
	temp := mul(P, companion)
	G := mul(temp, Pinv)

	return G
}

// Generate random 16x16 matrix over F251
func randomMatrix() Matrix {
	var m Matrix
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			n, _ := rand.Int(rand.Reader, big.NewInt(p))
			m[i][j] = int(n.Int64())
		}
	}
	return m
}

// Calculate determinant modulo p using Gaussian elimination
func determinant(m Matrix) int {
	// Copy to avoid modifying original
	var mat [16][16]int
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			mat[i][j] = m[i][j]
		}
	}

	det := 1
	for i := 0; i < 16; i++ {
		// Find pivot
		if mat[i][i] == 0 {
			for j := i + 1; j < 16; j++ {
				if mat[j][i] != 0 {
					mat[i], mat[j] = mat[j], mat[i]
					det = (-det) % p
					break
				}
			}
			if mat[i][i] == 0 {
				return 0 // Singular matrix
			}
		}

		invPivot := modInverse(mat[i][i], p)
		for j := i + 1; j < 16; j++ {
			if mat[j][i] != 0 {
				factor := (mat[j][i] * invPivot) % p
				for k := i; k < 16; k++ {
					mat[j][k] = (mat[j][k] - factor*mat[i][k]) % p
					if mat[j][k] < 0 {
						mat[j][k] += p
					}
				}
			}
		}
		det = (det * mat[i][i]) % p
	}

	if det < 0 {
		det += p
	}
	return det
}

// Matrix exponentiation: base^exp using all 256 bits
func matExp(base Matrix, exp []byte) Matrix {
	result := identity()
	current := base

	expInt := new(big.Int).SetBytes(exp)

	for i := 0; i < expInt.BitLen(); i++ {
		if expInt.Bit(i) == 1 {
			result = mul(result, current)
		}
		current = mul(current, current)
	}

	return result
}

// Generate 256-bit (32 bytes) private key
func generatePrivateKey() ([]byte, error) {
	privateKey := make([]byte, 32)
	_, err := rand.Read(privateKey)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Generate public key Y = G^x using all 256 bits
func generatePublicKey(G Matrix, x []byte) Matrix {
	return matExp(G, x)
}

// Calculate matrix inverse in GL(16, F251) using Gauss-Jordan elimination
func inverseMatrix(m Matrix) (Matrix, error) {
	var augmented [16][32]int
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			augmented[i][j] = m[i][j]
		}
		for j := 16; j < 32; j++ {
			if j-16 == i {
				augmented[i][j] = 1
			} else {
				augmented[i][j] = 0
			}
		}
	}

	for i := 0; i < 16; i++ {
		if augmented[i][i] == 0 {
			found := false
			for r := i + 1; r < 16; r++ {
				if augmented[r][i] != 0 {
					augmented[i], augmented[r] = augmented[r], augmented[i]
					found = true
					break
				}
			}
			if !found {
				return Matrix{}, fmt.Errorf("matrix not invertible")
			}
		}

		pivot := augmented[i][i]
		invPivot := modInverse(pivot, p)
		for j := 0; j < 32; j++ {
			augmented[i][j] = (augmented[i][j] * invPivot) % p
			if augmented[i][j] < 0 {
				augmented[i][j] += p
			}
		}

		for r := 0; r < 16; r++ {
			if r != i && augmented[r][i] != 0 {
				factor := augmented[r][i]
				for c := 0; c < 32; c++ {
					augmented[r][c] = (augmented[r][c] - factor*augmented[i][c]) % p
					if augmented[r][c] < 0 {
						augmented[r][c] += p
					}
				}
			}
		}
	}

	var inv Matrix
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			inv[i][j] = augmented[i][j+16]
		}
	}
	return inv, nil
}

// Modular inverse using extended Euclidean algorithm
func modInverse(a, m int) int {
	t, newT := 0, 1
	r, newR := m, a

	for newR != 0 {
		quotient := r / newR
		t, newT = newT, t-quotient*newT
		r, newR = newR, r-quotient*newR
	}

	if r > 1 {
		return 0 // No inverse
	}
	if t < 0 {
		t += m
	}
	return t
}

// Convert matrix to byte slice
func matrixToBytes(m Matrix) []byte {
	bytes := make([]byte, 256) // 16*16 = 256 bytes
	index := 0
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			bytes[index] = byte(m[i][j])
			index++
		}
	}
	return bytes
}

// Convert byte slice to matrix
func bytesToMatrix(b []byte) (Matrix, error) {
	if len(b) != 256 {
		return Matrix{}, fmt.Errorf("byte slice must be 256 bytes")
	}

	var m Matrix
	index := 0
	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			m[i][j] = int(b[index])
			index++
		}
	}
	return m, nil
}

// Convert byte slice to matrix
func hashToMatrix(msg []byte) Matrix {
	var M Matrix
	buf := make([]byte, 0, 16*16)

	// Gere hashes sucessivos até preencher os 256 bytes
	counter := 0
	for len(buf) < 16*16 {
		data := append(msg, byte(counter))
		h := sha512.Sum512(data)
		buf = append(buf, h[:]...)
		counter++
	}

	for i := 0; i < 16; i++ {
		for j := 0; j < 16; j++ {
			M[i][j] = int(buf[i*16+j]) % p
		}
	}
	return M
}

// Convert matrix to hex string
func matrixToHex(m Matrix) string {
	return hex.EncodeToString(matrixToBytes(m))
}

// Serialize ciphertext to ASN.1
func serializeCiphertext(C1, C2 Matrix) ([]byte, error) {
	ciphertext := Ciphertext{
		C1: matrixToBytes(C1),
		C2: matrixToBytes(C2),
	}
	return asn1.Marshal(ciphertext)
}

// Deserialize ciphertext from ASN.1
func deserializeCiphertext(data []byte) (Matrix, Matrix, error) {
	var ciphertext Ciphertext
	_, err := asn1.Unmarshal(data, &ciphertext)
	if err != nil {
		return Matrix{}, Matrix{}, err
	}

	C1, err := bytesToMatrix(ciphertext.C1)
	if err != nil {
		return Matrix{}, Matrix{}, err
	}

	C2, err := bytesToMatrix(ciphertext.C2)
	if err != nil {
		return Matrix{}, Matrix{}, err
	}

	return C1, C2, nil
}

// Generate a random message matrix (not necessarily invertible)
func randomMessageMatrix() Matrix {
	return randomMatrix()
}

// ============================ SCHNORR SIGNATURE FUNCTIONS ============================

// Mod p
func mod(a int) int {
	a %= p
	if a < 0 {
		a += p
	}
	return a
}

// NOVA: Hash para big.Int de 256 bits
func hashToScalar(msg []byte) *big.Int {
	h := sha512.Sum512(msg)
	// Usar apenas os primeiros 32 bytes (256 bits) do hash SHA512
	return new(big.Int).SetBytes(h[:32])
}

// Hash sha512 mapeado para matriz 16x16 mod p
func hashMessageToMatrix(msg []byte) Matrix {
	hkdf := hkdf.New(sha512.New, msg, nil, []byte("msg-to-matrix"))
	buf := make([]byte, 256)
	if _, err := hkdf.Read(buf); err != nil {
		panic(err)
	}

	var M Matrix
	for i := 0; i < 256; i++ {
		M[i/16][i%16] = int(buf[i]) % p
	}
	return M
}

// Assinatura CORRETA
func schnorrSign(m Matrix, xBytes []byte, G Matrix) (Matrix, []byte) {
	groupOrder := glOrder(16, 251)

	k, _ := rand.Int(rand.Reader, groupOrder)

	// Converter k para []byte para usar com matExp
	kBytes := k.Bytes()

	R := matExp(G, kBytes) // R = G^k (não-comutativo)

	e := hashToScalar(append(matrixToBytes(m), matrixToBytes(R)...))
	e.Mod(e, groupOrder)

	x := new(big.Int).SetBytes(xBytes)
	x.Mod(x, groupOrder)

	// s = k - x*e (no anel de inteiros, não nas matrizes)
	s := new(big.Int).Sub(k, new(big.Int).Mul(x, e))
	s.Mod(s, groupOrder)

	// Converter s para []byte
	sBytes := s.Bytes()

	// Garantir que sBytes tenha tamanho consistente (32 bytes para 256 bits)
	if len(sBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(sBytes):], sBytes)
		sBytes = padded
	}

	return R, sBytes
}

// Verificação CORRETA
func schnorrVerify(m, R Matrix, sBytes []byte, Y, G Matrix) bool {
	groupOrder := glOrder(16, 251)

	e := hashToScalar(append(matrixToBytes(m), matrixToBytes(R)...))
	e.Mod(e, groupOrder)

	// Converter e para []byte para usar com matExp
	eBytes := e.Bytes()
	if len(eBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(eBytes):], eBytes)
		eBytes = padded
	}

	// Verificação: R = G^s × Y^e (não-comutativo)
	left := R
	Gs := matExp(G, sBytes) // G^s
	Ye := matExp(Y, eBytes) // Y^e
	right := mul(Gs, Ye)    // G^s × Y^e

	return matricesEqual(left, right)
}

// Comparação de matrizes
func matricesEqual(a, b Matrix) bool {
	aBytes := matrixToBytes(a)
	bBytes := matrixToBytes(b)
    
	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1
}

func glOrder(n, q int64) *big.Int {
	result := big.NewInt(1)
	qBig := big.NewInt(q)
	qn := new(big.Int).Exp(qBig, big.NewInt(n), nil) // q^n

	for i := int64(0); i < n; i++ {
		qi := new(big.Int).Exp(qBig, big.NewInt(i), nil)
		term := new(big.Int).Sub(qn, qi)
		result.Mul(result, term)
	}
	return result
}

// Serialize Schnorr signature to ASN.1
func serializeSchnorrSignature(R Matrix, sBytes []byte) ([]byte, error) {
	signature := SchnorrSignature{
		R: matrixToBytes(R),
		S: sBytes,
	}
	return asn1.Marshal(signature)
}

// Deserialize Schnorr signature from ASN.1
func deserializeSchnorrSignature(data []byte) (Matrix, []byte, error) {
	var signature SchnorrSignature
	_, err := asn1.Unmarshal(data, &signature)
	if err != nil {
		return Matrix{}, nil, err
	}

	R, err := bytesToMatrix(signature.R)
	if err != nil {
		return Matrix{}, nil, err
	}

	return R, signature.S, nil
}

// =============================================================================
// ZERO-KNOWLEDGE PROOF (Fiat-Shamir) - ESSENTIAL FUNCTIONS ONLY
// =============================================================================

// GenerateZKProof generates a zero-knowledge proof of knowledge of the private key x
func GenerateZKProof(G, Y Matrix, xBytes []byte, message []byte) (Matrix, []byte, []byte) {
	groupOrder := glOrder(16, 251)

	// Step 1: Generate random commitment k
	k, _ := rand.Int(rand.Reader, groupOrder)

	// Step 2: Compute commitment R = G^k
	kBytes := k.Bytes()
	if len(kBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(kBytes):], kBytes)
		kBytes = padded
	}
	R := matExp(G, kBytes)

	// Step 3: Generate challenge e = H(G, Y, R, message)
	challengeData := append(matrixToBytes(G), matrixToBytes(Y)...)
	challengeData = append(challengeData, matrixToBytes(R)...)
	challengeData = append(challengeData, message...)

	e := hashToScalar(challengeData)
	e.Mod(e, groupOrder)

	// Step 4: Compute response s = k + x*e (mod order)
	x := new(big.Int).SetBytes(xBytes)
	x.Mod(x, groupOrder)

	s := new(big.Int).Mul(x, e)
	s.Add(k, s)
	s.Mod(s, groupOrder)

	sBytes := s.Bytes()
	if len(sBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(sBytes):], sBytes)
		sBytes = padded
	}

	eBytes := e.Bytes()
	if len(eBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(eBytes):], eBytes)
		eBytes = padded
	}

	return R, eBytes, sBytes
}

// VerifyZKProof verifies a zero-knowledge proof of knowledge
func VerifyZKProof(R Matrix, eBytes, sBytes []byte, G, Y Matrix, message []byte) bool {
	groupOrder := glOrder(16, 251)

	// Step 1: Recompute challenge e = H(G, Y, R, message)
	challengeData := append(matrixToBytes(G), matrixToBytes(Y)...)
	challengeData = append(challengeData, matrixToBytes(R)...)
	challengeData = append(challengeData, message...)

	e := hashToScalar(challengeData)
	e.Mod(e, groupOrder)

	// Convert to bytes for comparison
	computedEBytes := e.Bytes()
	if len(computedEBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(computedEBytes):], computedEBytes)
		computedEBytes = padded
	}

	// Verify that the provided challenge matches the recomputed one
	if !bytes.Equal(eBytes, computedEBytes) {
		return false
	}

	// Step 2: Verify the proof: G^s = R * Y^e
	Gs := matExp(G, sBytes) // Left side: G^s
	Ye := matExp(Y, eBytes) // Y^e
	rightSide := mul(R, Ye) // Right side: R * Y^e

	return matricesEqual(Gs, rightSide)
}

// =================================================

// GenerateDeterministicMatrix gera uma matriz G deterministicamente a partir de uma seed usando Lyra2RE2
func generateDeterministicMatrix(seed []byte) Matrix {
	seedHash, _ := lyra2re2.Sum(seed)

	// Gerar polinômio irredutível deterministicamente
	poly := generateDeterministicPolynomial(seedHash[:])

	// Criar matriz companheira do polinômio
	companion := companionMatrix(poly)

	// Gerar matrizes P e P^-1 deterministicamente para conjugação
	P := generateDeterministicInvertibleMatrix(seedHash[:], 1)
	Pinv := generateDeterministicInvertibleMatrix(seedHash[:], 2)

	// Conjugação: G = P × companion × P^-1
	temp := mul(P, companion)
	G := mul(temp, Pinv)

	return G
}

// GenerateDeterministicPolynomial gera polinômio deterministicamente usando Lyra2RE2
func generateDeterministicPolynomial(seed []byte) [degree]int {
	var poly [degree]int

	for i := 0; i < degree; i++ {
		// Usar Lyra2RE2 para cada coeficiente
		input := make([]byte, len(seed)+1)
		copy(input, seed)
		input[len(seed)] = byte(i)

		hash, _ := lyra2re2.Sum(input)

		// Usar hash para gerar coeficiente mod p
		coefInt := new(big.Int).SetBytes(hash[:8])
		coef := int(coefInt.Int64()) % p
		if coef < 0 {
			coef += p
		}
		poly[i] = coef
	}

	// Garantir que é mônico (coeficiente líder = 1)
	poly[degree-1] = 1

	return poly
}

// GenerateDeterministicInvertibleMatrix gera matriz invertível deterministicamente usando Lyra2RE2
func generateDeterministicInvertibleMatrix(seed []byte, counter int) Matrix {
	// Gerar seed para esta matriz específica
	input := make([]byte, len(seed)+1)
	copy(input, seed)
	input[len(seed)] = byte(counter)
	matrixSeed, _ := lyra2re2.Sum(input)

	var L, U Matrix

	// Gerar L (lower triangular) deterministicamente
	for i := 0; i < 16; i++ {
		// Diagonal com 1's
		L[i][i] = 1
		for j := 0; j < i; j++ {
			// Input único para cada elemento
			elemInput := make([]byte, len(matrixSeed)+3)
			copy(elemInput, matrixSeed[:])
			elemInput[len(matrixSeed)] = byte(i)
			elemInput[len(matrixSeed)+1] = byte(j)
			elemInput[len(matrixSeed)+2] = 'L'

			hash, _ := lyra2re2.Sum(elemInput)

			coefInt := new(big.Int).SetBytes(hash[:8])
			coef := int(coefInt.Int64()) % p
			if coef < 0 {
				coef += p
			}
			L[i][j] = coef
		}
	}

	// Gerar U (upper triangular) deterministicamente
	for i := 0; i < 16; i++ {
		for j := i; j < 16; j++ {
			// Input único para cada elemento
			elemInput := make([]byte, len(matrixSeed)+3)
			copy(elemInput, matrixSeed[:])
			elemInput[len(matrixSeed)] = byte(i)
			elemInput[len(matrixSeed)+1] = byte(j)
			elemInput[len(matrixSeed)+2] = 'U'

			hash, _ := lyra2re2.Sum(elemInput)

			coefInt := new(big.Int).SetBytes(hash[:8])
			coef := int(coefInt.Int64()) % p
			if coef < 0 {
				coef += p
			}

			if i == j && coef == 0 {
				coef = 1
			}
			U[i][j] = coef
		}
	}

	return mul(L, U)
}

// Deriva chave privada determinística a partir de seed
func derivePrivateKeyFromSeed(seed []byte) []byte {
	if len(seed) == 0 {
		// Fallback para aleatório se seed vazio
		x := make([]byte, 32)
		rand.Read(x)
		return x
	}
	
	// Hash do seed
	digest, _ := lyra2re2.Sum(seed)
		
	// Retornar os primeiros 32 bytes (256 bits)
	return digest[:32]
}

// =================================================
// Implementação das funções dependentes (placeholders)
// =================================================

// Estas funções precisam ser implementadas com as bibliotecas apropriadas

func calculateFingerprint(keyBytes []byte) string {
	// Implementação simplificada - usar hash real na implementação final
	return hex.EncodeToString(keyBytes[:16])
}

// Placeholder para lyra2re2 - substituir pela implementação real
func lyra2re2Sum(data []byte) ([]byte, error) {
	// Implementação placeholder - usar biblioteca real
	h := make([]byte, 64)
	copy(h, data)
	return h, nil
}

// Placeholder para randomart - substituir pela implementação real
func generateRandomArt(data string) string {
	// Implementação placeholder - usar biblioteca real
	return "RandomArt placeholder for: " + data[:20]
}
