package slip39

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gonum.org/v1/gonum/stat/combin"
)

const (
	testPassphrase = "TREZOR"
)

var (
	reRange = regexp.MustCompile(`^(?:(\d+)?(-))?(\d+)$`)

	// vectorErrors maps vector index to expected error
	vectorErrors = map[int]error{
		2:  ErrInvalidChecksum,
		3:  ErrInvalidPadding{},
		5:  ErrTooFewShares{},
		6:  ErrInvalidCommonParameters,
		7:  ErrInvalidCommonParameters,
		8:  ErrInvalidCommonParameters,
		9:  ErrInvalidCommonParameters,
		10: ErrBadGroupThreshold{},
		11: ErrInvalidMnemonicIndices,
		12: ErrTooManyShares{},
		13: ErrInvalidMnemonicSharedSecretDigest,
		14: ErrTooFewShares{},
		15: ErrTooFewShares{},
		16: ErrTooFewShares{},
		21: ErrInvalidChecksum,
		22: ErrInvalidPadding{},
		24: ErrTooFewShares{},
		25: ErrInvalidCommonParameters,
		26: ErrInvalidCommonParameters,
		27: ErrInvalidCommonParameters,
		28: ErrInvalidCommonParameters,
		29: ErrBadGroupThreshold{},
		30: ErrInvalidMnemonicIndices,
		31: ErrTooManyShares{},
		32: ErrInvalidMnemonicSharedSecretDigest,
		33: ErrTooFewShares{},
		34: ErrTooFewShares{},
		35: ErrTooFewShares{},
		39: ErrInvalidMnemonic,
		40: ErrInvalidPadding{},
	}
)

type vector struct {
	description    string
	shares         []string
	masterSecret   string
	rootPrivateKey string
}

type secret struct {
	Description       string
	MasterSecret      string                  `json:"master_secret"`
	GroupThreshold    int                     `json:"group_threshold"`
	MemberGroupParams []MemberGroupParameters `json:"member_group_params"`
}

func mustLoadVectors(t *testing.T) []vector {
	t.Helper()

	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}

	var records [][]interface{}
	err = json.Unmarshal(data, &records)
	if err != nil {
		t.Fatal(err)
	}

	vectors := make([]vector, len(records))
	for i, record := range records {
		v := vector{}
		v.description = record[0].(string)
		shares := record[1].([]interface{})
		v.shares = make([]string, len(shares))
		for j, s := range shares {
			v.shares[j] = s.(string)
		}
		v.masterSecret = record[2].(string)
		//v.rootPrivateKey = record[3].(string)
		vectors[i] = v
	}

	return vectors
}

func mustLoadSecrets(t *testing.T) []secret {
	t.Helper()

	data, err := os.ReadFile("testdata/secrets.json")
	if err != nil {
		t.Fatal(err)
	}

	var secrets []secret
	err = json.Unmarshal(data, &secrets)
	if err != nil {
		t.Fatal(err)
	}

	return secrets
}

func parseArgs(t *testing.T) (int, int) {
	t.Helper()

	finalArg := os.Args[len(os.Args)-1]
	matches := reRange.FindStringSubmatch(finalArg)
	var m1, m3 int
	var m2 string
	var err error
	if matches != nil {
		if matches[1] != "" {
			m1, err = strconv.Atoi(matches[1])
			if err != nil {
				t.Fatal(err)
			}
		}
		if matches[2] != "" {
			m2 = matches[2]
		}
		if matches[3] != "" {
			m3, err = strconv.Atoi(matches[3])
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	to := m3
	from := 0
	if m1 > 0 {
		// range with both ends defined e.g. 10-43
		from = m1
	} else if m2 != "" {
		// range with right-end-only defined e.g. -43
		from = 1
	} else {
		// simple number e.g. 43
		from = m3
	}

	return from, to
}

// Text xor
func TestXor(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		a    []byte
		b    []byte
		want []byte
	}{
		{[]byte{0, 1, 2, 3}, []byte{0, 2, 4, 6}, []byte{0, 3, 6, 5}},
		{[]byte{0, 1, 2, 3}, []byte{0, 2}, []byte{0, 3}},
	}

	for _, tc := range tests {
		got := xor(tc.a, tc.b)
		if string(got) != string(tc.want) {
			t.Errorf("getSalt failed: got %v, want %v", got, tc.want)
		}
	}
}

// Test getSalt
func TestGetSalt(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		id   int
		ext  bool
		want string
	}{
		{7945, false, "shamir\x1f\t"},
		{25653, false, "shamird5"},
	}

	for _, tc := range tests {
		got := getSalt(tc.id, tc.ext)
		if string(got) != tc.want {
			t.Errorf("getSalt failed: got %q, want %q", string(got), tc.want)
		}
	}
}

// Test round-tripping ParseShare and share.Mnemonic()
func TestParseShareMnemonic(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name  string
		input string
		err   error
	}{
		{"m1", "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard", nil},
		// Error cases
		{"mnemonic bad word", "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision bogus", ErrInvalidMnemonicWord{}},
		{"mnemonic bad length", "duckling enlarge", ErrInvalidMnemonic},
	}

	for _, tc := range tests {
		//t.Logf("input: %v", tc.input)
		s, err := ParseShare(tc.input)
		if err != nil {
			if tc.err == nil {
				t.Error(err)
			} else if !errors.Is(err, tc.err) {
				t.Errorf("unexpected error on %q: want %q, got %q",
					tc.name, tc.err, err)
			} else {
				_ = err.Error()
			}
			continue
		}
		//t.Logf("shareValues: %v", s.ShareValues)
		mnemonic, err := s.Mnemonic()
		if err != nil {
			if tc.err == nil {
				t.Error(err)
			}
			continue
		}
		//t.Logf("mnemonic: %s", mnemonic)
		if mnemonic != tc.input {
			t.Errorf("error on %q: input %q, output %q",
				tc.name, tc.input, mnemonic)
		}
	}
}

// Test round-tripping cipherEncrypt and cipherDecrypt
func TestCipherEncryptDecrypt(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		secret string
		id     int
		err    error
	}{
		{"bb54aac4b89dc868ba37d9cc21b2cece", 342, nil},
		{"bb", 342, ErrInvalidMasterSecretLength},
	}

	for _, tc := range tests {
		encrypted, err := cipherEncrypt([]byte(tc.secret), []byte(testPassphrase), 1, tc.id, true)
		if err != nil {
			if tc.err == nil {
				t.Fatal(err)
			}
			if !errors.Is(err, tc.err) {
				t.Errorf("got unexpected error: want %q, got %q",
					tc.err.Error(), err.Error())
			} else {
				continue
			}
		}
		decrypted, err := cipherDecrypt(encrypted, []byte(testPassphrase), 1, tc.id, true)
		if string(decrypted) != tc.secret {
			t.Errorf("want %q, got %q", tc.secret, string(decrypted))
		}
	}
}

func TestCombineMnemonics(t *testing.T) {
	t.Parallel()

	vectors := mustLoadVectors(t)
	from, to := parseArgs(t)

	for i, v := range vectors {
		if from > 0 && i+1 < from {
			continue
		}

		mnemonics := []string{}
		for _, m := range v.shares {
			mnemonics = append(mnemonics, m)
		}
		masterSecretBytes, err := CombineMnemonicsWithPassphrase(
			mnemonics, []byte(testPassphrase),
		)
		if err != nil {
			// If masterSecret is empty, then an error is expected
			if v.masterSecret != "" {
				t.Errorf("CombineMnemonics returned (unexpected) error: %s (%q)",
					err.Error(), v.description)
			} else if vectorErrors[i+1] != nil && !errors.Is(err, vectorErrors[i+1]) {
				t.Errorf("CombineMnemonics returned (unexpected) error type: %s (%q)",
					err.Error(), v.description)
			} else {
				_ = err.Error()
				/*
					t.Logf("CombineMnemonics returned (expected) error:%s (%q)",
						err.Error(), v.description)
				*/
			}
		} else if v.masterSecret == "" {
			t.Errorf("CombineMnemonics unexpectedly succeeded (%q)",
				v.description)
		} else {
			masterSecret := hex.EncodeToString(masterSecretBytes)
			if v.masterSecret != masterSecret {
				t.Errorf("CombineMnemonics returned bad masterSecret (got %v, want %q, for %q)",
					masterSecret, v.masterSecret, v.description)

				/*
					} else {
						t.Logf("CombineMnemonics success: %s (%q)",
							v.masterSecret, v.description)
				*/
			}
		}

		if to > 0 && i+1 >= to {
			break
		}
	}
}

func selectRandomShares(mgp MemberGroupParameters, shares []string) []string {
	if len(shares) == 1 {
		return []string{shares[0]}
	}
	list := combin.Combinations(mgp.MemberCount, mgp.MemberThreshold)
	i, err := rand.Int(rand.Reader, big.NewInt(int64(len(list))))
	if err != nil {
		panic("rand.Int failed:" + err.Error())
	}
	return selectShares(list[int(i.Int64())], shares)
}

func selectShares(selection []int, shares []string) []string {
	selected := make([]string, len(selection))
	for i, j := range selection {
		selected[i] = shares[j]
	}
	return selected
}

func selectAndFlattenSets(selection []int, sets [][]string) []string {
	selected := []string{}
	for _, j := range selection {
		for _, s := range sets[j] {
			selected = append(selected, s)
		}
	}
	return selected
}

func selectionString(selection []int) string {
	var s []string
	for _, i := range selection {
		s = append(s, strconv.Itoa(i))
	}
	return strings.Join(s, ",")
}

func checkSelectedMnemonics(
	t *testing.T,
	s secret,
	passphrase string,
	selectedIndices []int,
	selected []string,
) {
	var masterSecretBytes []byte
	var err error
	if passphrase != "" {
		masterSecretBytes, err = CombineMnemonicsWithPassphrase(
			selected, []byte(passphrase),
		)
	} else {
		masterSecretBytes, err = CombineMnemonics(selected)
	}
	if err != nil {
		t.Errorf("CombineMnemonics returned error: %q on mnemonics [%s] %v",
			err.Error(), selectionString(selectedIndices), selected)
		return
	}

	masterSecret := hex.EncodeToString(masterSecretBytes)
	if err != nil {
		t.Errorf("hex.EncodeToString returned error: %s", err.Error())
	}

	if masterSecret != s.MasterSecret {
		t.Errorf("masterSecret mismatch: got %q, want %q",
			string(masterSecret), s.MasterSecret)
		/*
			} else {
				t.Logf("masterSecret match with mnemonics [%s]: %v",
					selectionString(selectedIndices), selected)
		*/
	}

	// Check that deleting a random share from selected gives an error
	if len(selected) > 1 {
		i, err := rand.Int(rand.Reader, big.NewInt(int64(len(selected))))
		if err != nil {
			t.Fatalf("rand.Int failed: %s", err.Error())
		}
		j := int(i.Int64())
		selected2 := make([]string, len(selected)-1)
		copy(selected2, selected[:j])
		if len(selected) > j {
			copy(selected2[j:], selected[j+1:])
		}
		_, err = CombineMnemonicsWithPassphrase(
			selected2, []byte(passphrase),
		)
		if err == nil {
			t.Errorf("CombineMnemonics unexpectedly succeeded with k-1 mnemonics (%d) %v",
				len(selected2), selected2)
		} else if !errors.Is(err, ErrTooFewShares{}) {
			t.Errorf("CombineMnemonics failed with unexpected error with k-1 mnemonics (%d) %v: %s",
				len(selected2), selected2, err.Error())
		} else {
			_ = err.Error()
			//t.Logf("CombineMnemonics failed as expected with k-1 mnemonics (%d) %v", len(selected2), selected2)
		}
	}
}

// Test round-tripping GenerateMnemonics/CombineMnemonics
func TestGenerateMnemonics(t *testing.T) {
	t.Parallel()

	secrets := mustLoadSecrets(t)
	from, to := parseArgs(t)

	for _, passphrase := range []string{testPassphrase, ""} {
		for i, s := range secrets {
			if from > 0 && i+1 < from {
				continue
			}
			//fmt.Fprintf(os.Stderr, "secret: %v\n", s)

			masterSecretBytes, err := hex.DecodeString(s.MasterSecret)
			if err != nil {
				t.Errorf("hex.DecodeString returned error: %s", err.Error())
			}

			var shareGroups ShareGroups
			if passphrase != "" {
				shareGroups, err = GenerateMnemonicsWithOptions(
					s.GroupThreshold, s.MemberGroupParams,
					masterSecretBytes, []byte(passphrase),
					true, 0, // for some reason the python cli defaults to exponent=0
				)
			} else {
				shareGroups, err = GenerateMnemonics(
					s.GroupThreshold, s.MemberGroupParams, masterSecretBytes,
				)
			}
			if err != nil {
				t.Error(err)
			}
			//t.Logf("shareGroups (%d group(s)): %v\n", len(shareGroups), shareGroups)

			//secretBytes, combinations, err := shareGroups.ValidateMnemonicsWithPassphrase([]byte(passphrase))
			secretBytes, _, err := shareGroups.ValidateMnemonicsWithPassphrase([]byte(passphrase))
			if err != nil {
				if err == ErrTooManyCombinations {
					continue
				}
				t.Fatal(err)
			}
			secret := hex.EncodeToString(secretBytes)
			if secret != s.MasterSecret {
				t.Fatalf("ValidateMnemonics secret mismatch: got %q, want %q",
					secret, s.MasterSecret)
			}
			//t.Logf("combinations: %d, secret: %s", combinations, secret)

			if to > 0 && i+1 >= to {
				break
			}
		}
	}
}

// Test ShareGroups.combinations method
func TestShareGroupsCombinations(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		groupThreshold    int
		memberGroupParams []MemberGroupParameters
		quorumLength      int
	}{
		// Test: 1 of: 3of5
		{1, []MemberGroupParameters{{3, 5}}, 3},
		// Test: 2 of: 1of1 + 2of3
		{2, []MemberGroupParameters{{1, 1}, {2, 3}}, 3},
		// Test: 2 of: 2of3 + 3of5
		{2, []MemberGroupParameters{{2, 3}, {3, 5}}, 5},
		// Test: 2 of: 1of1 + 2of3 + 2of3
		{2, []MemberGroupParameters{{1, 1}, {2, 3}, {2, 3}}, 0},
	}

	secret := "989baf9dcaad5b10ca33dfd8cc75e42477025dce88ae83e75a230086a0e00e92"
	secretBytes, err := hex.DecodeString(secret)
	if err != nil {
		t.Errorf("hex.DecodeString returned error: %s", err.Error())
	}

	for _, tc := range tests {
		shareGroups, err := GenerateMnemonics(
			tc.groupThreshold, tc.memberGroupParams, secretBytes,
		)
		if err != nil {
			t.Fatal(err)
		}
		/*
			for i, sg := range shareGroups {
				t.Logf("shareGroup %d:\n%s\n", i, strings.Join(sg, "\n"))
			}
		*/

		groupCombinations, err := shareGroups.combinations()
		if err != nil {
			t.Fatal(err)
		}
		//t.Logf("groupCombinations: %d", len(groupCombinations))

		// Test validity:
		// - the number of shares should be as expected (quorumLength)
		// - the combinations of shares should be unique (no repeats)
		// - shares should all combine back to the same expected secret
		cache := make(map[string]int)
		for i, mnemonics := range groupCombinations {
			/*
				t.Logf("shareGroup %d mnemonics (%d):\n%s\n",
					i, len(mnemonics), strings.Join(mnemonics, "\n"))
			*/
			// Check number of shares
			if tc.quorumLength != 0 && len(mnemonics) != tc.quorumLength {
				t.Errorf("shareGroup %d combinations (%d) != %d", i,
					len(mnemonics), tc.quorumLength)
			}
			// Check uniqueness
			sort.Strings(mnemonics)
			key := strings.Join(mnemonics, "\n")
			cache[key]++
			if cache[key] > 1 {
				t.Errorf("shareGroup %d combinations not unique (count == %d):\n%s",
					i, cache[key], key)
			}
			// Check resultant secret
			masterSecretBytes, err := CombineMnemonics(mnemonics)
			if err != nil {
				t.Fatal(err)
			}
			masterSecret := hex.EncodeToString(masterSecretBytes)
			if masterSecret != secret {
				t.Errorf("shareGroup %d combined to unexpected secret: got %q, want %q",
					i, masterSecret, secret)
			}
		}
	}
}

// Test ShareGroups.String() and StringLabelled() methods
func TestShareGroupsStringMethods(t *testing.T) {
	t.Parallel()

	secrets := mustLoadSecrets(t)
	from, to := parseArgs(t)

	for i, s := range secrets {
		if from > 0 && i+1 < from {
			continue
		}
		//fmt.Fprintf(os.Stderr, "secret: %v\n", s)

		masterSecretBytes, err := hex.DecodeString(s.MasterSecret)
		if err != nil {
			t.Errorf("hex.DecodeString returned error: %s", err.Error())
		}

		shareGroups, err := GenerateMnemonics(
			s.GroupThreshold, s.MemberGroupParams, masterSecretBytes,
		)
		if err != nil {
			t.Error(err)
		}
		//t.Logf("shareGroups (%d group(s)): %v\n", len(shareGroups), shareGroups)

		str := shareGroups.String()
		//t.Logf("[%d] shareGroups.String(): %s", i+1, str)

		lstr, err := shareGroups.StringLabelled()
		if err != nil {
			t.Fatal(err)
		}
		//t.Logf("[%d] shareGroups.StringLabelled(): %s", i+1, lstr)

		// Recombine the labelled shares
		sg2, err := CombineLabelledShares(lstr)
		if err != nil {
			t.Fatal(err)
		}
		str2 := sg2.String()
		if str2 != str {
			t.Errorf("CombineLabelledShares mismatch: want:\n%sgot:\n%s",
				str, str2)
		}

		if to > 0 && i+1 >= to {
			break
		}
	}
}

// Test ShareGroups.StringLabelled() failures
func TestShareGroupsStringLabelled_Failures(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		label string
		input string
	}{
		// 3-digit SW non-consecutive wordNum
		{"3-digit SW non-consecutive wordNum",
			"101 duckling\n103 enlarge"},
		{"3-digit SW non-consecutive wordNum",
			"101 duckling\n101 enlarge"},
		{"3-digit SW non-consecutive wordNum",
			"102 duckling\n101 enlarge"},
		{"3-digit SW non-consecutive wordNum",
			"105 duckling\n101 enlarge"},
		// 3-digit SW non-consecutive shareNum
		{"3-digit SW non-consecutive shareNum",
			"101 duckling\n301 enlarge"},
		{"3-digit SW non-consecutive shareNum",
			"101 duckling\n101 enlarge"},
		{"3-digit SW non-consecutive shareNum",
			"301 duckling\n101 enlarge"},
		{"3-digit SW non-consecutive shareNum",
			"501 duckling\n201 enlarge"},
		// 4-digit SW non-consecutive wordNum
		{"4-digit SW non-consecutive wordNum",
			"0101 duckling\n0103 enlarge"},
		{"4-digit SW non-consecutive wordNum",
			"0101 duckling\n0101 enlarge"},
		{"4-digit SW non-consecutive wordNum",
			"0102 duckling\n0101 enlarge"},
		{"4-digit SW non-consecutive wordNum",
			"0105 duckling\n0101 enlarge"},
		// 4-digit SW non-consecutive shareNum
		{"4-digit SW non-consecutive shareNum",
			"0101 duckling\n0301 enlarge"},
		{"4-digit SW non-consecutive shareNum",
			"0101 duckling\n0101 enlarge"},
		{"4-digit SW non-consecutive shareNum",
			"0301 duckling\n0101 enlarge"},
		{"4-digit SW non-consecutive shareNum",
			"0501 duckling\n0201 enlarge"},
		// 5-digit GSW non-consecutive wordNum
		{"5-digit GSW non-consecutive wordNum",
			"10101 duckling\n10103 enlarge"},
		{"5-digit GSW non-consecutive wordNum",
			"10101 duckling\n10101 enlarge"},
		{"5-digit GSW non-consecutive wordNum",
			"10102 duckling\n10101 enlarge"},
		{"5-digit GSW non-consecutive wordNum",
			"10105 duckling\n10101 enlarge"},
		// 5-digit GSW non-consecutive shareNum
		{"5-digit GSW non-consecutive shareNum",
			"10101 duckling\n10301 enlarge"},
		{"5-digit GSW non-consecutive shareNum",
			"10101 duckling\n10101 enlarge"},
		{"5-digit GSW non-consecutive shareNum",
			"10301 duckling\n10101 enlarge"},
		{"5-digit GSW non-consecutive shareNum",
			"10501 duckling\n10201 enlarge"},
		// 5-digit GSW non-consecutive groupNum
		{"5-digit GSW non-consecutive groupNum",
			"10101 duckling\n10101 enlarge"},
		{"5-digit GSW non-consecutive groupNum",
			"20101 duckling\n10101 enlarge"},
		{"5-digit GSW non-consecutive groupNum",
			"30101 duckling\n10101 enlarge"},
		{"5-digit GSW non-consecutive groupNum",
			"10101 duckling\n30101 enlarge"},
		{"5-digit GSW non-consecutive groupNum",
			"10101 duckling\n90101 enlarge"},
		// 5-digit GSW non-consecutive wordNum
		{"5-digit GSW non-consecutive wordNum",
			"01101 duckling\n01103 enlarge"},
		{"5-digit GSW non-consecutive wordNum",
			"01101 duckling\n01101 enlarge"},
		{"5-digit GSW non-consecutive wordNum",
			"01102 duckling\n01101 enlarge"},
		{"5-digit GSW non-consecutive wordNum",
			"01105 duckling\n01101 enlarge"},
		// 5-digit GSW non-consecutive shareNum
		{"5-digit GSW non-consecutive shareNum",
			"01101 duckling\n01301 enlarge"},
		{"5-digit GSW non-consecutive shareNum",
			"01101 duckling\n01101 enlarge"},
		{"5-digit GSW non-consecutive shareNum",
			"01301 duckling\n01101 enlarge"},
		{"5-digit GSW non-consecutive shareNum",
			"01501 duckling\n01201 enlarge"},
		// 5-digit GSW non-consecutive groupNum
		{"5-digit GSW non-consecutive groupNum",
			"01101 duckling\n01101 enlarge"},
		{"5-digit GSW non-consecutive groupNum",
			"02101 duckling\n01101 enlarge"},
		{"5-digit GSW non-consecutive groupNum",
			"03101 duckling\n01101 enlarge"},
		{"5-digit GSW non-consecutive groupNum",
			"01101 duckling\n03101 enlarge"},
		{"5-digit GSW non-consecutive groupNum",
			"01101 duckling\n09101 enlarge"},
		// 6-digit GSW non-consecutive wordNum
		{"6-digit GSW non-consecutive wordNum",
			"010101 duckling\n010103 enlarge"},
		{"6-digit GSW non-consecutive wordNum",
			"010101 duckling\n010101 enlarge"},
		{"6-digit GSW non-consecutive wordNum",
			"010102 duckling\n010101 enlarge"},
		{"6-digit GSW non-consecutive wordNum",
			"010105 duckling\n010101 enlarge"},
		// 6-digit GSW non-consecutive shareNum
		{"6-digit GSW non-consecutive shareNum",
			"010101 duckling\n010301 enlarge"},
		{"6-digit GSW non-consecutive shareNum",
			"010101 duckling\n010101 enlarge"},
		{"6-digit GSW non-consecutive shareNum",
			"010301 duckling\n010101 enlarge"},
		{"6-digit GSW non-consecutive shareNum",
			"010501 duckling\n010201 enlarge"},
		// 6-digit GSW non-consecutive groupNum
		{"6-digit GSW non-consecutive groupNum",
			"010101 duckling\n010101 enlarge"},
		{"6-digit GSW non-consecutive groupNum",
			"020101 duckling\n010101 enlarge"},
		{"6-digit GSW non-consecutive groupNum",
			"030101 duckling\n010101 enlarge"},
		{"6-digit GSW non-consecutive groupNum",
			"010101 duckling\n030101 enlarge"},
		{"6-digit GSW non-consecutive groupNum",
			"010101 duckling\n090101 enlarge"},
		// Mixed-style labels
		{"Mixed-style labels",
			"010101 duckling\n0102 enlarge"},
		{"Mixed-style labels",
			"0101 duckling\n10102 enlarge"},
	}

	for _, tc := range tests {
		sg, err := CombineLabelledShares(tc.input)
		if err == nil {
			t.Errorf("%q test unexpectedly passed:\n%s", tc.label, sg.String())
			/*
				} else {
					t.Logf("%q test failed as expected: %s", tc.label, err.Error())
			*/
		}
	}
}
