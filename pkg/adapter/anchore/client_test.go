package anchore

import (
//	"github.com/anchore/harbor-scanner-adapter/pkg/model/anchore"
	"sort"
	"testing"
)

//func TestVulnQueryChunking(t *testing.T) {
//	s := []interface{}{
//		VulnNamespaceDescription{
//			id: "a",
//			namespace: "a",
//			description: "",
//		},
//		VulnNamespaceDescription{
//			id: "b",
//			namespace: "a",
//			description: "",
//		},
//		VulnNamespaceDescription{
//			id: "c",
//			namespace: "a",
//			description: "",
//		},
//		VulnNamespaceDescription{
//			id: "d",
//			namespace: "a",
//			description: "",
//		},
//		VulnNamespaceDescription{
//			id: "e",
//			namespace: "a",
//			description: "",
//		},
//		VulnNamespaceDescription{
//			id: "f",
//			namespace: "a",
//			description: "",
//		},
//		VulnNamespaceDescription{
//			id: "g",
//			namespace: "a",
//			description: "",
//		},
//		VulnNamespaceDescription{
//			id: "i",
//			namespace: "a",
//			description: "",
//		},
//	}
//
//	result, err := getVulnProcessingChunks(s, 3)
//	if err != nil {
//		t.Error(err)
//	}
//
//	t.Logf("Results: %v", result)
//
//	if len(result) != 3 {
//		t.Fatal("incorrect result length")
//	}
//
//	if len(result[0]) != 3 || len(result[1]) != 3 || len(result[2]) != 2 {
//		t.Fatalf("incorrect chunk lenght %v", result)
//	}
//}

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
		return vulns[i].namespace < vulns[j].namespace
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
