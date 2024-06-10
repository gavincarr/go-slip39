package slip39

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const (
	testPassphrase = "TREZOR"
	//testPassphrase = ""
)

type vector struct {
	description    string
	shares         []string
	masterSecret   string
	rootPrivateKey string
}

func loadVectors(t *testing.T) ([]vector, error) {
	t.Helper()

	data, err := os.ReadFile("vectors.json")
	if err != nil {
		return nil, err
	}

	var records [][]interface{}
	err = json.Unmarshal(data, &records)
	if err != nil {
		return nil, err
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

	return vectors, nil
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

// Test round-tripping ParseShare and share.words()
func TestParseShareWords(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name  string
		input string
	}{
		{"m1", "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard"},
	}

	for _, tc := range tests {
		//t.Logf("input: %v", tc.input)
		s, err := parseShare(tc.input)
		if err != nil {
			t.Fatal(err)
		}
		//t.Logf("shareValues: %v", s.ShareValues)
		w, err := s.words()
		if err != nil {
			t.Fatal(err)
		}
		words := strings.Join(w, " ")
		//t.Logf("words: %s", words)
		if words != tc.input {
			t.Errorf("error on %s: input %q, output %q", tc.name, tc.input, words)
		}
	}
}

func TestCombineMnemonics(t *testing.T) {
	t.Parallel()

	vectors, err := loadVectors(t)
	if err != nil {
		t.Fatal(err)
	}

	for i, v := range vectors {
		mnemonics := []string{}
		for _, m := range v.shares {
			mnemonics = append(mnemonics, m)
		}
		masterSecretBytes, err := CombineMnemonics(mnemonics, []byte(testPassphrase))
		if err != nil {
			// If masterSecret is empty, then an error is expected
			if v.masterSecret == "" {
				t.Logf("CombineMnemonics returned (expected) error:%s (%q)",
					err.Error(), v.description)
			} else {
				t.Errorf("CombineMnemonics returned (unexpected) error: %s (%q)",
					err.Error(), v.description)

			}
		} else if v.masterSecret == "" {
			t.Errorf("CombineMnemonics unexpectedly succeeded (%q)",
				v.description)
		} else {
			masterSecret := hex.EncodeToString(masterSecretBytes)
			if v.masterSecret != masterSecret {
				t.Errorf("CombineMnemonics returned bad masterSecret (got %v, want %q, for %q)",
					masterSecret, v.masterSecret, v.description)

			} else {
				t.Logf("CombineMnemonics success: %s (%q)",
					v.masterSecret, v.description)
			}
		}
		if i+1 >= 4 {
			break
		}
	}
}
