package client

import (
	"sort"
	"testing"
)

func TestSorting(t *testing.T) {
	vulns := []VulnNamespaceDescription{
		{
			"id1",
			"namespace1",
			"",
		},
		{
			"id2",
			"namespace2",
			"",
		},
		{
			"id3",
			"namespace1",
			"",
		},
	}

	less := func(i, j int) bool {
		return vulns[i].Namespace < vulns[j].Namespace
	}

	sort.Slice(vulns, less)
	t.Logf("sorted %v", vulns)
}

func TestChunkFunction(t *testing.T) {
	// Ensure start and end are correct, remembering end is for slicing, so it is the last index + 1
	start, end := getVulnProcessingChunks(10, 0, 10)
	if start != 0 || end != 10 {
		t.Fatal("Incorrect index: ", start, end)
	}

	start, end = getVulnProcessingChunks(100, 1, 10)
	if start != 10 || end != 20 {
		t.Fatal("Incorrect index: ", start, end)
	}
}

func TestExtractRegistryFromUrl(t *testing.T) {
	registries := [][]string{
		// Ok, should work
		{"http://core.harbor.domain:8080", "core.harbor.domain:8080"},
		{"https://core.harbor.domain:8080", "core.harbor.domain:8080"},
		{"https://core.harbor.domain", "core.harbor.domain"},
		{"https://core.harbor.domain/path/v1/", "core.harbor.domain"},
		// These fail since no scheme.
		{"core.harbor.domain", ""},
		{"core.harbor.domain:8080", ""},
	}

	for _, r := range registries {
		expected := r[1]
		input := r[0]
		got, err := ExtractRegistryFromUrl(input)
		if err != nil {
			if expected != "" {
				t.Errorf("error on %v: %v", input, err)
			} else {
				t.Log("got expected error on input", input)
			}
		} else if got != expected {
			t.Errorf("Expected %v, Got %v", r[1], got)
		}
	}
	return
}
