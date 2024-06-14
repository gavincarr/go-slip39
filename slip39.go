// Package slip39 is a Go implementation of the SLIP-0039 spec, implementing
// Shamir's Secret Sharing Scheme.
//
// The official SLIP-0039 spec can be found at
// https://github.com/satoshilabs/slips/blob/master/slip-0039.md
package slip39

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/xdg-go/pbkdf2"
)

const (
	minMnemonicLengthWords        = 20
	customizationStringOriginal   = "shamir"
	customizationStringExtendable = "shamir_extendable"

	radixBits                = 10
	idLengthBits             = 15
	extendableFlagLengthBits = 1
	iterationExpLengthBits   = 4
	idExpLengthWords         = 2
	groupPrefixLengthWords   = idExpLengthWords + 1
	maxShareCount            = 16
	checksumLengthWords      = 3
	digestLengthBytes        = 4
	metadataLengthWords      = idExpLengthWords + 2 + checksumLengthWords
	minStrengthBits          = 128

	shift5Bits  = 1 << 5
	shift10Bits = 1 << 10
	last10Bits  = 1<<10 - 1
	shift30Bits = 1 << 30
	last30Bits  = 1<<30 - 1

	// cipher constants
	baseIterationCount = 10000 // The minimum number of iterations for PBKDF2
	roundCount         = 4     // The number of rounds to use in the Feistel cipher
	secretIndex        = 255   // The index of the shared secret share
	digestIndex        = 254   // The index of the shared secret digest share
)

var (
	bigOne          = big.NewInt(1)
	shift5BitsMask  = big.NewInt(shift5Bits)
	shift10BitsMask = big.NewInt(shift10Bits)
	last10BitsMask  = big.NewInt(last10Bits)
	shift30BitsMask = big.NewInt(shift30Bits)
	last30BitsMask  = big.NewInt(last30Bits)

	expTable = []int{}
	logTable = []int{}
)

var (
	// ErrInvalidChecksum is returned when the checksum on a mnemonic is invalid
	ErrInvalidChecksum = errors.New("invalid checksum")

	// ErrInvalidMnemonic is returned when a mnemonic is invalid
	ErrInvalidMnemonic = errors.New("invalid mnemonic")

	// ErrEmptyShareGroup is returned when a share group is empty
	ErrEmptyShareGroup = errors.New("the share group is empty")

	// ErrMaxShareCountExceeded
	ErrMaxShareCountExceeded = fmt.Errorf("the number of shares cannot exceed %d", maxShareCount)

	// ErrInvalidGroupThreshold is returned when the group threshold is invalid
	ErrInvalidGroupThreshold = errors.New("group threshold must be a positive integers and must not exceed the number of groups")

	// ErrInvalidThreshold is returned when the threshold is invalid
	ErrInvalidThreshold = errors.New("the requested threshold must be a positive integers and must not exceed the number of shares")

	// ErrInvalidSingleMemberThreshold is returned when the group threshold is invalid
	ErrInvalidSingleMemberThreshold = errors.New("cannot create multiple member shares with member threshold 1 - use 1-of-1 member sharing instead")

	// ErrInvalidMnemonicIndices is returned when a set of shares contains
	// non-unique share indices
	ErrInvalidMnemonicIndices = errors.New("invalid set of shares - share indices must be unique")

	// ErrInvalidMnemonicShareLengths is returned with a set of shares include
	// shares with different lengths
	ErrInvalidMnemonicShareLengths = errors.New("invalid set of shares - all share values must have the same length")

	// ErrInvalidMnemonicSharedSecretDigest is returned when a mnemonic has an
	// invalid shared secret digest
	ErrInvalidMnemonicSharedSecretDigest = errors.New("invalid shared secret digest")

	// ErrInvalidMasterSecretLength is returned when trying to use a (decrypted)
	// master secret with an invalid length
	ErrInvalidMasterSecretLength = errors.New("master secret length must be >= 16B and be a multiple of 2")

	// ErrInvalidEncryptedMasterSecretLength is returned when an encrypted master
	// secret has an invalid length
	ErrInvalidEncryptedMasterSecretLength = errors.New("the length of the encrypted master secret must be an even number")

	// ErrInvalidPassphrase is returned when a passphrase contains invalid
	// characters
	ErrInvalidPassphrase = errors.New("the passphrase must contain only printable ASCII characters (code points 32-126)")
)

// MemberGroupParameters define the (MemberThreshold, MemberCount) pairs required
// for the share groups created by GenerateMnemonics. MemberCount is the number
// of shares to generate for the group, and MemberThreshold is the number of
// members required to reconstruct the group secret.
type MemberGroupParameters struct {
	MemberThreshold int `json:"member_threshold"`
	MemberCount     int `json:"member_count"`
}

type shareCommonParameters struct {
	identifier        int
	extendable        int
	iterationExponent int
	groupThreshold    int
	groupCount        int
}

type shareGroupParameters struct {
	shareCommonParameters
	groupIndex      int
	memberThreshold int
}

type shareStruct struct {
	shareGroupParameters
	index       int
	shareValues []byte
}

type shareGroup struct {
	shares []shareStruct
}

type shareGroupMap map[int]shareGroup

type rawShare struct {
	x    int
	data []byte
}

type encryptedMasterSecret struct {
	identifier        int
	extendable        bool
	iterationExponent int
	ciphertext        []byte
}

func newEncryptedMasterSecret(
	masterSecret, passphrase []byte,
	identifier int,
	extendable bool,
	iteration_exponent int,
) (encryptedMasterSecret, error) {
	ciphertext, err := cipherEncrypt(
		masterSecret, passphrase, iteration_exponent, identifier, extendable,
	)
	if err != nil {
		return encryptedMasterSecret{}, err
	}
	return encryptedMasterSecret{
		identifier:        identifier,
		extendable:        extendable,
		iterationExponent: iteration_exponent,
		ciphertext:        ciphertext,
	}, nil
}

func (ems encryptedMasterSecret) decrypt(passphrase []byte) ([]byte, error) {
	return cipherDecrypt(ems.ciphertext, passphrase,
		ems.iterationExponent, ems.identifier, ems.extendable)
}

func zipBytes(a, b []byte) [][2]byte {
	length := len(a)
	if len(b) < length {
		length = len(b)
	}
	zip := make([][2]byte, length)
	for i := range length {
		x := byte(0)
		y := byte(0)
		if len(a) > i {
			x = a[i]
		}
		if len(b) > i {
			y = b[i]
		}
		zip[i] = [2]byte{x, y}
	}
	return zip
}

func xor(a, b []byte) []byte {
	c := zipBytes(a, b)
	xor := make([]byte, len(c))
	for i := range len(c) {
		xor[i] = c[i][0] ^ c[i][1]
	}
	return xor
}

func roundFunction(i int, passphrase []byte, e int, salt, r []byte) []byte {
	b := append([]byte{byte(i)}, passphrase...)
	s := append(salt, r...)
	iterations := (baseIterationCount << e) / roundCount
	return pbkdf2.Key(b, s, iterations, len(r), sha256.New)
}

func getSalt(identifier int, extendable bool) []byte {
	if extendable {
		return []byte{}
	}
	idBytes := [2]byte{}
	binary.BigEndian.PutUint16(idBytes[:], uint16(identifier))
	return append([]byte(customizationStringOriginal), idBytes[0], idBytes[1])
}

func cipherEncrypt(
	masterSecret, passphrase []byte,
	iterationExponent, identifier int,
	extendable bool,
) ([]byte, error) {
	if len(masterSecret)%2 != 0 {
		return nil, ErrInvalidMasterSecretLength
	}

	l := masterSecret[:len(masterSecret)/2]
	r := masterSecret[len(masterSecret)/2:]
	salt := getSalt(identifier, extendable)
	for i := range roundCount {
		f := roundFunction(i, passphrase, iterationExponent, salt, r)
		l, r = r, xor(l, f)
	}
	return append(r, l...), nil
}

func cipherDecrypt(
	ems, passphrase []byte,
	iterationExponent, identifier int,
	extendable bool,
) ([]byte, error) {
	if len(ems)%2 != 0 {
		return nil, ErrInvalidEncryptedMasterSecretLength
	}

	l := ems[:len(ems)/2]
	r := ems[len(ems)/2:]
	salt := getSalt(identifier, extendable)
	for i := roundCount - 1; i >= 0; i-- {
		f := roundFunction(i, passphrase, iterationExponent, salt, r)
		l, r = r, xor(l, f)
	}

	return append(r, l...), nil
}

func splitMnemonicWords(mnemonic string) ([]string, bool) {
	words := strings.Fields(mnemonic)

	if len(words) < minMnemonicLengthWords {
		return nil, false
	}

	return words, true
}

// roundBits returns the number of `radixBits`-sized digits required to store a
// `n`-bit value
func roundBits(bits, radixBits int) int {
	return (bits + radixBits - 1) / radixBits
}

// padByteSlice returns a byte slice of the given size with contents of the
// given slice left padded and any empty spaces filled with zeros
func padByteSlice(slice []byte, length int) []byte {
	offset := length - len(slice)
	if offset <= 0 {
		return slice
	}

	newSlice := make([]byte, length)
	copy(newSlice[offset:], slice)

	return newSlice
}

func intToIndices(value, length, bits int) []int {
	mask := (1 << bits) - 1
	indices := make([]int, 0, length)
	for i := length - 1; i >= 0; i-- {
		indices = append(indices, (value>>(i*bits))&mask)
	}
	return indices
}

// bitesToBytes rounds up bit count to bytes
func bitsToBytes(bits int) int {
	return roundBits(bits, 8)
}

// bitsToWords rounds up bit count to a multiple of radixBits word size
func bitsToWords(bits int) int {
	return roundBits(bits, radixBits)
}

func stringToInts(s string) []int {
	ints := make([]int, len(s))
	for i := 0; i < len(s); i++ {
		ints[i] = int(s[i])
	}
	return ints
}

func intFromWordIndices(indices []int) int {
	if len(indices) > 4 {
		panic("intFromWordIndices: indices length must be <= 4")
	}
	value := 0
	for _, index := range indices {
		value = (value << radixBits) + index
	}
	return value
}

func bigintFromWordIndices(indices []int) *big.Int {
	var wordBytes [2]byte
	var b = big.NewInt(0)
	for _, index := range indices {
		binary.BigEndian.PutUint16(wordBytes[:], uint16(index))
		b.Mul(b, shift10BitsMask)
		b.Or(b, big.NewInt(0).SetBytes(wordBytes[:]))
	}
	return b
}

func intToWordIndices(value int, length int) []int {
	return intToIndices(value, length, radixBits)
}

func bigintToWordIndices(b *big.Int, length int) []int {
	indices := make([]int, length)
	// Throwaway big.Int for AND masking
	word := big.NewInt(0)
	for i := length - 1; i >= 0; i-- {
		// Get 10 rightmost bits and bitshift 10 to the right
		word.And(b, last10BitsMask)
		b.Div(b, shift10BitsMask)

		// Get the bytes representing the 10 bits as a 2-byte slice
		wordBytes := padByteSlice(word.Bytes(), 2)

		// Converts wordBytes to an index and add to indices
		indices[i] = int(binary.BigEndian.Uint16(wordBytes))
	}
	return indices
}

func rs1024Polymod(values []int) int {
	gen := []int{
		0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009,
		0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120,
	}
	chk := 1

	for _, v := range values {
		b := chk >> 20
		chk = ((chk & 0xfffff) << 10) ^ v
		for i := range 10 {
			if (b>>i)&1 != 0 {
				chk ^= gen[i]
			} else {
				chk ^= 0
			}
		}
	}

	return chk
}

func rs1024VerifyChecksum(cs string, data []int) bool {
	values := append(stringToInts(cs), data...)
	return rs1024Polymod(values) == 1
}

func rs1024CreateChecksum(data []int, cs string) []int {
	values := append(stringToInts(cs), data...)
	values = append(values, []int{0, 0, 0}...)
	polymod := rs1024Polymod(values) ^ 1
	checksum := make([]int, checksumLengthWords)
	for i := range checksumLengthWords {
		checksum[i] = (polymod >> (10 * (2 - i))) & 1023
	}
	return checksum
}

func (s shareStruct) encodeIDExp() []int {
	idExpInt := s.identifier << (iterationExpLengthBits + extendableFlagLengthBits)
	idExpInt += s.extendable << iterationExpLengthBits
	idExpInt += s.iterationExponent
	return intToWordIndices(idExpInt, idExpLengthWords)
}

func (s shareStruct) encodeShareParams() []int {
	// Each value is 4 bits, for 20 bits total
	val := s.groupIndex
	val <<= 4
	val += s.groupThreshold - 1
	val <<= 4
	val += s.groupCount - 1
	val <<= 4
	val += s.index
	val <<= 4
	val += s.memberThreshold - 1
	// Group parameters are 2 words
	return intToWordIndices(val, 2)
}

func (s shareStruct) encode(valueData []int) []int {
	shareData := []int{}
	shareData = append(shareData, s.encodeIDExp()...)
	shareData = append(shareData, s.encodeShareParams()...)
	shareData = append(shareData, valueData...)
	return shareData
}

func (s shareStruct) customizationString() string {
	if s.extendable != 0 {
		return customizationStringExtendable
	}
	return customizationStringOriginal
}

// words converts share data to a share mnemonic
func (s shareStruct) words() ([]string, error) {
	valueWordCount := bitsToWords(len(s.shareValues) * 8)
	valueInt := big.NewInt(0).SetBytes(s.shareValues)
	valueData := bigintToWordIndices(valueInt, valueWordCount)

	shareData := s.encode(valueData)
	checksum := rs1024CreateChecksum(shareData, s.customizationString())
	//fmt.Fprintf(os.Stderr, "shareData: %v, customizationString: %s, checksum: %v\n",
	//shareData, s.customizationString(), checksum)
	shareData = append(shareData, checksum...)

	words := make([]string, 0, len(shareData))
	for _, wordIndex := range shareData {
		word := wordlist[wordIndex]
		if word == "" {
			return nil, fmt.Errorf("invalid share wordIndex %d", wordIndex)
		}
		words = append(words, word)
	}
	return words, nil
}

func (s shareStruct) mnemonic() (string, error) {
	words, err := s.words()
	if err != nil {
		return "", err
	}
	return strings.Join(words, " "), nil
}

func parseShare(mnemonic string) (shareStruct, error) {
	var share shareStruct

	mnemonicData, isValid := splitMnemonicWords(strings.ToLower(mnemonic))
	if !isValid {
		return share, ErrInvalidMnemonic
	}

	paddingLen := (radixBits * (len(mnemonicData) - metadataLengthWords)) % 16
	//fmt.Fprintf(os.Stderr, "paddingLen: %d\n", paddingLen)
	if paddingLen > 8 {
		return share, ErrInvalidMnemonic
	}

	var data = make([]int, len(mnemonicData))
	for i, v := range mnemonicData {
		index, found := wordmap[v]
		if !found {
			return share,
				fmt.Errorf("Invalid mnemonic: word `%v` not found in wordmap", v)
		}
		data[i] = index
	}
	//fmt.Fprintf(os.Stderr, "data: %v\n", data)

	idExpData := data[:idExpLengthWords]
	idExpInt := intFromWordIndices(idExpData)
	//fmt.Fprintf(os.Stderr, "idExpInt: %d\n", idExpInt)

	share.identifier = idExpInt >>
		(extendableFlagLengthBits + iterationExpLengthBits)
	share.extendable = idExpInt >> iterationExpLengthBits & 1
	share.iterationExponent = idExpInt & ((1 << iterationExpLengthBits) - 1)

	// Verify checksum
	cs := share.customizationString()
	/*
		fmt.Fprintf(os.Stderr, "createChecksum: %v\n",
			rs1024CreateChecksum(customizationStringOriginal,
				data[:len(data)-checksumLengthWords]))
	*/
	if !rs1024VerifyChecksum(cs, data) {
		return share, ErrInvalidChecksum
	}

	shareParamsData := data[idExpLengthWords : idExpLengthWords+2]
	shareParamsInt := intFromWordIndices(shareParamsData)
	shareParams := intToIndices(shareParamsInt, 5, 4)
	share.groupIndex = shareParams[0]
	share.groupThreshold = shareParams[1] + 1
	share.groupCount = shareParams[2] + 1
	share.index = shareParams[3]
	share.memberThreshold = shareParams[4] + 1

	if share.groupCount < share.groupThreshold {
		return share,
			fmt.Errorf(`Invalid mnemonic "%s ...". Group threshold cannot be greater than group count`,
				strings.Join(mnemonicData[:idExpLengthWords+2], " "))
	}

	valueData := data[idExpLengthWords+2 : len(data)-checksumLengthWords]
	valueByteCount := bitsToBytes(radixBits*len(valueData) - paddingLen)
	//fmt.Fprintf(os.Stderr, "valueByteCount: %d\n", valueByteCount)
	valueInt := bigintFromWordIndices(valueData)
	//fmt.Fprintf(os.Stderr, "valueInt: %d\n", valueInt)
	valueBytes := valueInt.Bytes()
	if len(valueBytes) > valueByteCount {
		return share,
			fmt.Errorf(`Invalid mnemonic padding for "%s ..."`,
				strings.Join(mnemonicData[:idExpLengthWords+2], " "))
	}
	valueBytes = make([]byte, valueByteCount)
	valueInt.FillBytes(valueBytes)
	share.shareValues = valueBytes
	//fmt.Fprintf(os.Stderr, "shareValues: %q (len %d)\n", share.shareValues, len(share.shareValues))

	return share, nil
}

// newShareGroupMap creates a new shareGroupMap from a slice of mnemonics,
// or returns an error.
func newShareGroupMap(mnemonics []string) (shareGroupMap, error) {
	commonParams := mapset.NewSet[shareCommonParameters]()
	groups := make(shareGroupMap)
	for _, mnemonic := range mnemonics {
		share, err := parseShare(mnemonic)
		if err != nil {
			return nil, err
		}
		//fmt.Fprintf(os.Stderr, "newShareGroupMap: share %v\n", share)
		commonParams.Add(share.shareCommonParameters)
		group, ok := groups[share.groupIndex]
		if !ok {
			groups[share.groupIndex] = shareGroup{shares: []shareStruct{share}}
		} else {
			group.shares = append(group.shares, share)
			groups[share.groupIndex] = group
		}
	}
	if commonParams.Cardinality() != 1 {
		return nil,
			fmt.Errorf("all mnemonics must begin with the same %d words, must have the same group threshold and the same group count", idExpLengthWords)
	}
	return groups, nil
}

func (group shareGroup) toRawShares() []rawShare {
	grs := make([]rawShare, len(group.shares))
	for i, s := range group.shares {
		grs[i] = rawShare{
			x:    s.index,
			data: s.shareValues,
		}
	}
	return grs
}

func precomputeExpLog() ([]int, []int) {
	expTable := make([]int, 255)
	logTable := make([]int, 256)

	poly := 1
	for i := range 255 {
		expTable[i] = poly
		logTable[poly] = i

		// Multiply poly by the polynomial x + 1
		poly = (poly << 1) ^ poly

		// Reduce poly by x^8 + x^4 + x^3 + x + 1
		if poly&0x100 != 0 {
			poly ^= 0x11B
		}
	}

	return expTable, logTable
}

// interpolate returns f(x) given the Shamir shares
// (x_1, f(x_1)), ... , (x_k, f(x_k))
func interpolate(shares []rawShare, x int) ([]byte, error) {
	xCoords := mapset.NewSetWithSize[int](len(shares))
	shareValueLengths := mapset.NewSetWithSize[int](len(shares))
	for _, share := range shares {
		xCoords.Add(share.x)
		shareValueLengths.Add(len(share.data))
	}

	if xCoords.Cardinality() != len(shares) {
		fmt.Fprintf(os.Stderr, "interpolate: shares %v, xCoords %v\n", shares, xCoords)
		return nil, ErrInvalidMnemonicIndices
	}
	if shareValueLengths.Cardinality() != 1 {
		//fmt.Fprintf(os.Stderr, "interpolate: shares %v, shareValueLengths %v\n", shares, shareValueLengths)
		return nil, ErrInvalidMnemonicShareLengths
	}

	if xCoords.Contains(x) {
		for _, share := range shares {
			if share.x == x {
				return share.data, nil
			}
		}
	}

	if len(expTable) == 0 {
		expTable, logTable = precomputeExpLog()
	}

	// Logarithm of the product of (x_i - x) for i = 1, ... , k.
	logProd := 0
	for _, share := range shares {
		logProd += logTable[share.x^x]
	}
	//fmt.Fprintf(os.Stderr, "interpolate1: shares %q, logProd %d\n", shares, logProd)

	length, _ := shareValueLengths.Pop()
	result := make([]byte, length)
	for _, share := range shares {
		// The logarithm of the Lagrange basis polynomial evaluated at x
		otherLog := 0
		for _, other := range shares {
			otherLog += logTable[share.x^other.x]
		}
		logBasisEval := (logProd - logTable[share.x^x] - otherLog) % 255
		// Adjust for python modulo behavior
		if logBasisEval < 0 {
			logBasisEval += 255
		}
		//fmt.Fprintf(os.Stderr, "interpolate2: logTable %d, otherlog %d, logBasisEval %d\n", logTable[share.x^x], otherLog, logBasisEval)

		intermediateSum := make([]byte, length)
		copy(intermediateSum, result)
		for j, shareVal := range share.data {
			expValue := 0
			if shareVal != 0 {
				expValue = expTable[(logTable[shareVal]+logBasisEval)%255]
			}
			result[j] = byte(intermediateSum[j] ^ byte(expValue))
		}
	}
	//fmt.Fprintf(os.Stderr, "interpolate3: result %q\n", result)

	return result, nil
}

func createDigest(randomData, sharedSecret []byte) []byte {
	digest := hmac.New(sha256.New, randomData)
	digest.Write(sharedSecret)
	return digest.Sum(nil)[:digestLengthBytes]
}

func recoverSecret(threshold int, shares []rawShare) ([]byte, error) {
	// If the threshold is 1, then the digest of the shared secret is not used
	if threshold == 1 {
		return shares[0].data, nil
	}

	sharedSecret, err := interpolate(shares, secretIndex)
	if err != nil {
		return nil, err
	}
	digestShare, err := interpolate(shares, digestIndex)
	if err != nil {
		return nil, err
	}
	digest := digestShare[:digestLengthBytes]
	randomPart := digestShare[digestLengthBytes:]

	checkDigest := createDigest(randomPart, sharedSecret)
	//fmt.Fprintf(os.Stderr, "recoverSecret: threshold %d, digestShare %q, randomPart %q, sharedSecret %q, digest %q, checkDigest %q \n", threshold, digestShare, randomPart, sharedSecret, digest, checkDigest)
	if bytes.Compare(digest, checkDigest) != 0 {
		return nil, ErrInvalidMnemonicSharedSecretDigest
	}

	return sharedSecret, nil
}

func splitSecret(
	threshold int,
	shareCount int,
	sharedSecret []byte,
) ([]rawShare, error) {
	if threshold < 1 || threshold > shareCount {
		return nil, ErrInvalidThreshold
	}
	if shareCount > maxShareCount {
		return nil, ErrMaxShareCountExceeded
	}

	// If the threshold is 1, then the digest of the shared secret is not used
	if threshold == 1 {
		shares := make([]rawShare, shareCount)
		for i := range shareCount {
			share := rawShare{
				x:    i,
				data: sharedSecret,
			}
			//fmt.Fprintf(os.Stderr, "splitSecret: share.data %q (%d)\n", share.data, len(share.data))
			shares[i] = share
		}
		return shares, nil
	}

	randomShareCount := threshold - 2

	shares := make([]rawShare, 0, shareCount)
	for i := range randomShareCount {
		randomBytes := make([]byte, len(sharedSecret))
		_, err := rand.Read(randomBytes)
		if err != nil {
			return shares,
				fmt.Errorf("error reading randomBytes bytes: %s", err.Error())
		}
		share := rawShare{
			x:    i,
			data: randomBytes,
		}
		shares = append(shares, share)
	}
	//fmt.Fprintf(os.Stderr, "splitSecret: shares1 %v\n", shares)
	baseShares := make([]rawShare, len(shares), shareCount)
	copy(baseShares, shares)

	randomPart := make([]byte, len(sharedSecret)-digestLengthBytes)
	_, err := rand.Read(randomPart)
	if err != nil {
		return shares,
			fmt.Errorf("error reading randomPart bytes: %s", err.Error())
	}
	digest := createDigest(randomPart, sharedSecret)
	//fmt.Fprintf(os.Stderr, "splitSecret: randomPart %q, sharedSecret %q, digest %q\n", randomPart, sharedSecret, digest)

	baseShares = append(baseShares, rawShare{
		x: digestIndex, data: append(digest, randomPart...),
	})
	baseShares = append(baseShares, rawShare{
		x: secretIndex, data: sharedSecret,
	})

	for i := randomShareCount; i < shareCount; i++ {
		data, err := interpolate(baseShares, i)
		if err != nil {
			return shares, fmt.Errorf("splitSecret interpolate error: %s", err)
		}
		//fmt.Fprintf(os.Stderr, "splitSecret: interpolate [%d] %q\n", i, data)

		shares = append(shares, rawShare{
			x: i, data: data,
		})
	}
	//fmt.Fprintf(os.Stderr, "splitSecret: shares[%d] %q\n", s.x, s.data)

	return shares, nil
}

func splitEMS(
	groupThreshold int,
	mgplist []MemberGroupParameters,
	ems encryptedMasterSecret,
) ([][]shareStruct, error) {
	// TODO: test all these error conditions
	if len(ems.ciphertext)*8 < minStrengthBits {
		return nil, ErrInvalidMasterSecretLength
	}
	if groupThreshold > len(mgplist) {
		return nil, ErrInvalidGroupThreshold
	}
	for _, mgp := range mgplist {
		if mgp.MemberThreshold == 1 && mgp.MemberCount > 1 {
			return nil, ErrInvalidSingleMemberThreshold
		}
	}
	//fmt.Fprintf(os.Stderr, "splitEMS: groupThreshold %d, mgplist %v, ems.ciphertext %q\n", groupThreshold, mgplist, ems.ciphertext)

	groupShares, err := splitSecret(groupThreshold, len(mgplist), ems.ciphertext)
	if err != nil {
		return nil, err
	}

	groupedShares := make([][]shareStruct, 0, len(mgplist))
	for groupIndex, groupShare := range groupShares {
		mgp := mgplist[groupIndex]
		rawMemberShares, err := splitSecret(
			mgp.MemberThreshold, mgp.MemberCount, groupShare.data,
		)
		if err != nil {
			return nil, err
		}

		memberShares := make([]shareStruct, 0, len(rawMemberShares))
		extendable := 1
		if !ems.extendable {
			extendable = 0
		}
		sgp := shareGroupParameters{
			shareCommonParameters: shareCommonParameters{
				identifier:        ems.identifier,
				extendable:        extendable,
				iterationExponent: ems.iterationExponent,
				groupThreshold:    groupThreshold,
				groupCount:        len(mgplist),
			},
			groupIndex:      groupIndex,
			memberThreshold: mgp.MemberThreshold,
		}
		for memberIndex, value := range rawMemberShares {
			memberShares = append(memberShares, shareStruct{
				shareGroupParameters: sgp,
				index:                memberIndex,
				shareValues:          value.data,
			})
		}
		groupedShares = append(groupedShares, memberShares)
	}
	//fmt.Fprintf(os.Stderr, "splitEMS: groupedShares %v\n", groupedShares)

	return groupedShares, nil
}

// recoverEMS combines the shares in shareGroupMap, recovers the group metadata,
// and returns the encrypted master secret. If there are any problems with the
// share group it returns an error.
func recoverEMS(groups shareGroupMap) (encryptedMasterSecret, error) {
	ems := encryptedMasterSecret{}

	if len(groups) == 0 {
		return ems, ErrEmptyShareGroup
	}

	var params shareCommonParameters
	i := 0
	for _, group := range groups {
		if i == 0 {
			params = group.shares[0].shareCommonParameters
			if len(groups) < params.groupThreshold {
				return ems, fmt.Errorf("insufficient share groups (%d supplied, %d required)",
					len(groups), params.groupThreshold)
			}

			if len(groups) != params.groupThreshold {
				return ems, fmt.Errorf("wrong number of share groups (%d supplied, %d required)",
					len(groups), params.groupThreshold)
			}
		}

		//fmt.Fprintf(os.Stderr, "recoverEMS: group.shares %d, shares[0].memberThreshold %d\n", len(group.shares), group.shares[0].memberThreshold)
		if len(group.shares) != group.shares[0].memberThreshold {
			shareWords, err := group.shares[0].words()
			if err != nil {
				return ems, fmt.Errorf("wrong number of shares (%d supplied, %d required for group starting with %q)",
					len(group.shares), group.shares[0].memberThreshold,
					"unknown")
			}
			prefix := strings.Join(shareWords[:groupPrefixLengthWords], " ")
			return ems, fmt.Errorf("wrong number of shares (%d supplied, %d required for group starting with %q)",
				len(group.shares), group.shares[0].memberThreshold, prefix)
		}

		i++
	}

	groupShares := make([]rawShare, 0, len(groups))
	for groupIndex, group := range groups {
		grs := group.toRawShares()
		//fmt.Fprintf(os.Stderr, "recoverEMS: groupIndex %d, grs %v\n", groupIndex, grs)
		secret, err := recoverSecret(group.shares[0].memberThreshold, grs)
		if err != nil {
			return ems, err
		}
		//fmt.Fprintf(os.Stderr, "recoverEMS: groupIndex %d, groupRawShares %v, secret %v\n", groupIndex, grs, secret)
		groupShares = append(groupShares, rawShare{
			x:    groupIndex,
			data: secret,
		})
	}

	ciphertext, err := recoverSecret(params.groupThreshold, groupShares)
	if err != nil {
		return ems, err
	}

	return encryptedMasterSecret{
		identifier:        params.identifier,
		extendable:        params.extendable == 1,
		iterationExponent: params.iterationExponent,
		ciphertext:        ciphertext,
	}, nil
}

// CombineMnemonicWithPassphrases combines mnemonics protected with a passphrase
// to give the master secret which was originally split into shares using
// Shamir's Secret Sharing Scheme,
func CombineMnemonicsWithPassphrase(
	mnemonics []string,
	passphrase []byte,
) ([]byte, error) {
	if len(mnemonics) == 0 {
		return nil, errors.New("the list of mnemonics is empty")
	}

	groups, err := newShareGroupMap(mnemonics)
	if err != nil {
		return nil, err
	}
	//fmt.Fprintf(os.Stderr, "CombineMnemonicsWithPassphrase: %d mnemonic(s), %d group(s), %d share(s) in group 1, groups %v\n", len(mnemonics), len(groups), len(groups[0].shares), groups)
	ems, err := recoverEMS(groups)
	if err != nil {
		return nil, err
	}
	//fmt.Fprintf(os.Stderr, "CombineMnemonicsWithPassphrase: ems %v\n", ems)
	masterSecret, err := ems.decrypt(passphrase)
	if err != nil {
		return nil, err
	}

	return masterSecret, nil
}

// CombineMnemonics combines mnemonics into the master secret which was
// originally split into shares using Shamir's Secret Sharing Scheme
// (without a passphrase).
//
// The CombineMnenonics functions are the standard entry points for recovering
// the master secret from a set of slip39 mnemonics.
func CombineMnemonics(mnemonics []string) ([]byte, error) {
	return CombineMnemonicsWithPassphrase(mnemonics, []byte{})
}

func checkPassphrase(passphrase []byte) error {
	for _, c := range passphrase {
		if c < 32 || c > 126 {
			return ErrInvalidPassphrase
		}
	}
	return nil
}

// randomIdentifier returns a random idLengthBits identifier
func randomIdentifier() (int, error) {
	i, err := rand.Int(rand.Reader, big.NewInt(1<<idLengthBits))
	if err != nil {
		return -1, err
	}
	return int(i.Int64()) & ((1 << idLengthBits) - 1), nil
}

// GenerateMnemonicsWithOptions splits masterSecret into mnemonic shares
// using Shamir's secret sharing scheme.
// group_threshold is the number of groups required to reconstruct the master
// secret.
// groups is a slice of MemberGroupParameters, which contain ( MemberThreshold,
// MemberCount ) pairs for each group, where MemberCount is the number of
// shares to generate for the group, and MemberThreshold is the number of
// members required to reconstruct the group secret.
// masterSecret is the secret to split into shares, and passphrase is an
// optional passphrase to protect the shares.
// extendable is a boolean flag indicating whether the set of shares is
// 'extendable', allowing additional sets of shares to be created later
// for the same master secret (and passphrase, if used). Defaults to true.
// iterationExponent is the exponent used to derive the iteration count used
// in the PBKDF2 key derivation function. The number of iterations is
// calculated as 10000 * 2^iterationExponent. Defaults to 1.
func GenerateMnemonicsWithOptions(
	groupThreshold int,
	groups []MemberGroupParameters,
	masterSecret []byte,
	passphrase []byte,
	extendable bool,
	iterationExponent int,
) ([][]string, error) {
	if err := checkPassphrase(passphrase); err != nil {
		return nil, err
	}

	identifier, err := randomIdentifier()
	ems, err := newEncryptedMasterSecret(
		masterSecret, passphrase, identifier, extendable, iterationExponent,
	)
	if err != nil {
		return nil, err
	}
	//fmt.Fprintf(os.Stderr, "GenerateMnemonicsWithOptions ems: %v\n", ems)

	groupedShares, err := splitEMS(groupThreshold, groups, ems)
	if err != nil {
		return nil, err
	}

	groupMnemonics := make([][]string, 0, len(groupedShares))
	for _, group := range groupedShares {
		mnemonics := make([]string, 0, len(group))
		for _, share := range group {
			mnemonic, err := share.mnemonic()
			if err != nil {
				return nil, err
			}
			//fmt.Fprintf(os.Stderr, "GenerateMnemonics: share %v, mnemonic %q\n", share, mnemonic)
			mnemonics = append(mnemonics, mnemonic)
		}
		groupMnemonics = append(groupMnemonics, mnemonics)
	}

	return groupMnemonics, nil
}

// GenerateMnemonics splits masterSecret into mnemonic shares using Shamir's
// secret sharing scheme.
// See GenerateMnemonicsWithOptions for parameter documenantation.
//
// The GenerateMnenonics functions are the standard entry points for splitting
// a master secret into slip39 mnemonic shares.
func GenerateMnemonics(
	groupThreshold int,
	groups []MemberGroupParameters,
	masterSecret []byte,
) ([][]string, error) {
	return GenerateMnemonicsWithOptions(
		groupThreshold, groups, masterSecret, []byte{}, true, 1,
	)
}

// GenerateMnemonicsWithPassphrase splits masterSecret into mnemonic shares
// protected by a passphrase using Shamir's secret sharing scheme.
// See GenerateMnemonicsWithOptions for parameter documenantation.
func GenerateMnemonicsWithPassphrase(
	groupThreshold int,
	groups []MemberGroupParameters,
	masterSecret []byte,
	passphrase []byte,
) ([][]string, error) {
	return GenerateMnemonicsWithOptions(
		groupThreshold, groups, masterSecret, passphrase, true, 1,
	)
}
