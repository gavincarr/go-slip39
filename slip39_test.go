package slip39

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
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

func TestParseShare(t *testing.T) {
	t.Parallel()

	vectors, err := loadVectors(t)
	if err != nil {
		t.Fatal(err)
	}

	for i, v := range vectors {
		for j, s := range v.shares {
			share, err := ParseShare(s)
			fmt.Printf("%v\n", share)
			if err != nil {
				// If masterSecret is empty, then an error is expected
				if v.masterSecret == "" {
					t.Logf("ParseShare %d.%d returned (expected) error: %s (%q)",
						i+1, j+1, err.Error(), s)
				} else {
					t.Errorf("ParseShare %d.%d returned (unexpected) error: %s (%q)",
						i+1, j+1, err.Error(), s)

				}
			} else if v.masterSecret == "" {
				t.Errorf("ParseShare %d.%d unexpectedly succeeded (%q)",
					i+1, j+1, s)
			} else {
				t.Logf("ParseShare %d.%d ok (%q)", i+1, j+1, s)
			}
		}
		if i >= 3 {
			break
		}
	}
}
