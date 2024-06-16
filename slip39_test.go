package slip39

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"regexp"
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

	data, err := os.ReadFile("vectors.json")
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

	data, err := os.ReadFile("secrets.json")
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
	}{
		{"m1", "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard"},
	}

	for _, tc := range tests {
		//t.Logf("input: %v", tc.input)
		s, err := ParseShare(tc.input)
		if err != nil {
			t.Fatal(err)
		}
		//t.Logf("shareValues: %v", s.ShareValues)
		mnemonic, err := s.Mnemonic()
		if err != nil {
			t.Fatal(err)
		}
		//t.Logf("mnemonic: %s", mnemonic)
		if mnemonic != tc.input {
			t.Errorf("error on %s: input %q, output %q",
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
	}{
		{"bb54aac4b89dc868ba37d9cc21b2cece", 342},
	}

	for _, tc := range tests {
		encrypted, err := cipherEncrypt([]byte(tc.secret), []byte(testPassphrase), 1, tc.id, true)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("encrypted: %q", encrypted)
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
				/*
					} else {
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
	selectedIndices []int,
	selected []string,
) {
	masterSecretBytes, err := CombineMnemonicsWithPassphrase(
		selected, []byte(testPassphrase),
	)
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
	} else {
		t.Logf("masterSecret match with mnemonics [%s]: %v",
			selectionString(selectedIndices), selected)
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
			selected2, []byte(testPassphrase),
		)
		if err == nil {
			t.Errorf("CombineMnemonics unexpectedly succeeded with k-1 mnemonics (%d) %v",
				len(selected2), selected2)
		} else {
			t.Logf("CombineMnemonics failed as expected with k-1 mnemonics (%d) %v",
				len(selected2), selected2)
		}
	}
}

// Test round-tripping GenerateMnemonics/CombineMnemonics
func TestGenerateMnemonics(t *testing.T) {
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

		groupMnemonics, err := GenerateMnemonicsWithOptions(
			s.GroupThreshold, s.MemberGroupParams,
			masterSecretBytes, []byte(testPassphrase),
			true, 0, // for some reason the python cli defaults to exponent=0
		)
		if err != nil {
			t.Error(err)
		}
		//t.Logf("groupMnemonics (%d group(s)): %v\n", len(groupMnemonics), groupMnemonics)

		if s.GroupThreshold == 1 {
			for i, mnemonics := range groupMnemonics {
				// Test all threshold combinations of seeds
				mgp := s.MemberGroupParams[i]
				list := combin.Combinations(mgp.MemberCount, mgp.MemberThreshold)
				for _, selectedIndices := range list {
					selected := selectShares(selectedIndices, mnemonics)
					checkSelectedMnemonics(t, s, selectedIndices, selected)
				}
			}
		} else {
			// For multi-group test all combinations of groups with random
			// sets of threshold seeds
			groupSelections := make([][]string, 0, len(groupMnemonics))
			for i, mnemonics := range groupMnemonics {
				mgp := s.MemberGroupParams[i]
				selected := selectRandomShares(mgp, mnemonics)
				groupSelections = append(groupSelections, selected)
			}
			//t.Logf("groupSelections: %v", groupSelections)

			list := combin.Combinations(len(groupMnemonics), s.GroupThreshold)
			//t.Logf("selected: %v", list)
			for _, selectedIndices := range list {
				selected := selectAndFlattenSets(selectedIndices, groupSelections)
				//t.Logf("selected: %v", selected)
				checkSelectedMnemonics(t, s, selectedIndices, selected)
			}
		}

		if to > 0 && i+1 >= to {
			break
		}
	}
}
