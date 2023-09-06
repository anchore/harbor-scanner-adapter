package client

import (
	"sort"
	"testing"

	"github.com/anchore/harbor-scanner-adapter/pkg/model/anchore"
)

const (
	RegistryCredAddSuccess = `
		[
			{
				"created_at": "2019-10-28T18:43:59Z",
				"last_updated": "2019-10-28T18:43:59Z",
				"registry": "harbor:8443",
				"registry_name": "harbor:8443",
				"registry_type": "docker_v2",
				"registry_user": "robot",
				"registry_verify": true,
				"userId": "admin"
			}
		]`
	RegistryCredAddFailsExists = `
		{
			"detail": {
				"error_codes": []
			},
			"httpcode": 500,
			"message": "registry already exists in DB"
		}
		`
	GenericErrorResponse           = ""
	RegistryCredUpdateSuccess      = ""
	RegistryCredUpdateFailNotFound = ""
	RegistryCredAddValidateFailed  = `
		{
			"detail": {
				"error_codes": []
			},
			"httpcode": 406,
			"message": "cannot ping supplied registry with supplied credentials - exception: failed check to access registry (https://harbor:8443,robot) - exception: HTTPSConnectionPool(host='harbor', port=8443): Max retries exceeded with url: /v2/ (Caused by SSLError(SSLError(\"bad handshake: Error([('SSL routines', 'tls_process_server_certificate', 'certificate verify failed')],)\",),))"
		}`
	AddImageSuccess = `
		[
			{
				"analysis_status": "analyzed",
				"analyzed_at": "2019-10-24T10:31:01Z",
				"annotations": {},
				"created_at": "2019-10-24T10:19:06Z",
				"imageDigest": "sha256:ee6841b1e2bf99562a4d340cf9ef21ec87b016d1100e341aa77d5f53d04fc2c7",
				"image_content": {
					"metadata": {
						"arch": "amd64",
						"distro": "debian",
						"distro_version": "9",
						"dockerfile_mode": "Guessed",
						"image_size": 971079680,
						"layer_count": 9
					}
				},
				"image_detail": [
					{
						"created_at": "2019-10-24T10:19:06Z",
						"digest": "sha256:ee6841b1e2bf99562a4d340cf9ef21ec87b016d1100e341aa77d5f53d04fc2c7",
						"dockerfile": "",
						"fulldigest": "harbor:8443/library/node@sha256:ee6841b1e2bf99562a4d340cf9ef21ec87b016d1100e341aa77d5f53d04fc2c7",
						"fulltag": "harbor:8443/library/node:latest",
						"imageDigest": "sha256:ee6841b1e2bf99562a4d340cf9ef21ec87b016d1100e341aa77d5f53d04fc2c7",
						"imageId": "8ba21ece67434d95d7e36f55250b7a46de020fef63ad90277008b235b32845f2",
						"last_updated": "2019-10-24T10:31:01Z",
						"registry": "harbor:8443",
						"repo": "library/node",
						"tag": "latest",
						"tag_detected_at": "2019-10-24T10:19:06Z",
						"userId": "admin"
					}
				],
				"image_status": "active",
				"image_type": "docker",
				"last_updated": "2019-10-24T10:31:01Z",
				"parentDigest": "sha256:ee6841b1e2bf99562a4d340cf9ef21ec87b016d1100e341aa77d5f53d04fc2c7",
				"userId": "admin"
			}
		]`
	AddImageFailedSkopeoBadCreds = `
		{
			"detail": {
				"error_codes": [
					"REGISTRY_PERMISSION_DENIED"
				],
				"raw_exception_message": "Error encountered in skopeo operation. cmd=/bin/sh -c skopeo  inspect --raw --tls-verify=false  docker://harbor:8443/testproject/alpine:latest, rc=1, stdout=None, stderr=b'time=\"2019-10-28T18:40:56Z\" level=fatal msg=\"Error reading manifest latest in harbor:8443/testproject/alpine: errors:\\ndenied: requested access to the resource is denied\\nunauthorized: authentication required\\n\" \\n', error_code=REGISTRY_PERMISSION_DENIED"
			},
			"httpcode": 400,
			"message": "cannot fetch image digest/manifest from registry"
		}`
	AddImageFailedSkopeoNotFound = `
		{
			"detail": {
				"error_codes": [
					"REGISTRY_NOT_ACCESSIBLE"
				], 
				"raw_exception_message": "Error encountered in skopeo operation. cmd=/bin/sh -c skopeo  inspect --raw --tls-verify=false  docker://localhost:8443/notfound:latest, rc=1, stdout=None, stderr=b'time=\"2019-10-28T18:37:22Z\" level=fatal msg=\"pinging docker registry returned: Get http://localhost:8443/v2/: dial tcp 127.0.0.1:8443: connect: connection refused\" \\n', error_code=REGISTRY_NOT_ACCESSIBLE"
			},
			"httpcode": 400,
			"message": "cannot fetch image digest/manifest from registry"
			}`
) // #nosec G101

func TestSorting(t *testing.T) {
	vulns := []anchore.NamespacedVulnerability{
		{
			ID:          "id1",
			Namespace:   "namespace1",
			Description: "",
		},
		{
			ID:          "id2",
			Namespace:   "namespace2",
			Description: "",
		},
		{
			ID:          "id3",
			Namespace:   "namespace1",
			Description: "",
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
		got, err := ExtractRegistryFromURL(input)
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
}

func TestRegistryNameFromRepo(t *testing.T) {
	registries := [][]string{
		// Ok, should work
		{"http://core.harbor.domain:8080", "library", "core.harbor.domain:8080/library"},
		{
			"https://core.harbor.domain:8080",
			"testproject/repository/image",
			"core.harbor.domain:8080/testproject/repository/image",
		},
		{"https://core.harbor.domain", "some/repository/with/slashes", "core.harbor.domain/some/repository/with/slashes"},
		{"https://core.harbor.domain/path/v1/", "repo1", "core.harbor.domain/repo1"},
		// These fail since no scheme.
		{"core.harbor.domain", "", ""},
		{"core.harbor.domain:8080", "", ""},
	}

	for _, r := range registries {
		expected := r[2]
		input := r[0]
		got, err := RegistryNameFromRepo(r[0], r[1])
		if err != nil {
			if expected != "" {
				t.Errorf("error on %v: %v", input, err)
			} else {
				t.Log("got expected error on input", input)
			}
		} else if got != expected {
			t.Errorf("Expected %v, Got %v", r[2], got)
		}
	}
}
