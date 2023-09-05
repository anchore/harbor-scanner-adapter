package anchore

import (
	"fmt"
	"testing"
	"time"

	"github.com/anchore/harbor-scanner-adapter/pkg/model/harbor"
	"github.com/stretchr/testify/assert"
)

func TestMemoryResultStore_HasResult(t *testing.T) {
	type fields struct {
		Results map[string]VulnerabilityResult
	}
	type args struct {
		scanID string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name:   "result found and scan complete",
			fields: fields{Results: map[string]VulnerabilityResult{"test1": {ScanID: "test1", IsComplete: true}}},
			args:   args{"test1"},
			want:   true,
		},
		{
			name:   "result found and scan incomplete",
			fields: fields{Results: map[string]VulnerabilityResult{"test1": {ScanID: "test1", IsComplete: false}}},
			args:   args{"test1"},
			want:   false,
		},
		{
			name:   "result not found",
			fields: fields{Results: map[string]VulnerabilityResult{}},
			args:   args{"test1"},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MemoryResultStore{
				Results: tt.fields.Results,
			}
			got := m.HasResult(tt.args.scanID)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMemoryResultStore_PopResult(t *testing.T) {
	type fields struct {
		Results map[string]VulnerabilityResult
	}
	type args struct {
		scanID string
	}
	tests := []struct {
		name                              string
		fields                            fields
		args                              args
		want                              VulnerabilityResult
		want1                             bool
		expectedResultStoreAfterPopResult fields
	}{
		{
			name: "result found and scan complete",
			fields: fields{
				Results: map[string]VulnerabilityResult{"test1": {ScanID: "test1", IsComplete: true}},
			},
			args:                              args{"test1"},
			want:                              VulnerabilityResult{ScanID: "test1", IsComplete: true},
			want1:                             true,
			expectedResultStoreAfterPopResult: fields{Results: map[string]VulnerabilityResult{}},
		},
		{
			name: "result not found",
			fields: fields{
				Results: map[string]VulnerabilityResult{},
			},
			args:                              args{"test1"},
			want:                              VulnerabilityResult{},
			want1:                             false,
			expectedResultStoreAfterPopResult: fields{Results: map[string]VulnerabilityResult{}},
		},
		{
			name: "result found and scan incomplete",
			fields: fields{
				Results: map[string]VulnerabilityResult{"test1": {ScanID: "test1", IsComplete: false}},
			},
			args:  args{"test1"},
			want:  VulnerabilityResult{ScanID: "test1", IsComplete: false},
			want1: true,
			expectedResultStoreAfterPopResult: fields{
				Results: map[string]VulnerabilityResult{"test1": {ScanID: "test1", IsComplete: false}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MemoryResultStore{
				Results: tt.fields.Results,
			}
			got, got1 := m.PopResult(tt.args.scanID)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.want1, got1)
			assert.Equal(t, tt.expectedResultStoreAfterPopResult.Results, m.Results)
		})
	}
}

func TestMemoryResultStore_RequestResult(t *testing.T) {
	type fields struct {
		Results map[string]VulnerabilityResult
	}
	type args struct {
		scanID  string
		buildFn func() (*harbor.VulnerabilityReport, error)
	}
	resultStore = MemoryResultStore{Results: make(map[string]VulnerabilityResult, 1000)}
	resultChannel = make(chan VulnerabilityResult)
	testTime := time.Now()
	tests := []struct {
		name                  string
		fields                fields
		args                  args
		want                  VulnerabilityResult
		wantErr               bool
		wantResponseOnChannel bool
		wantChannelResult     VulnerabilityResult
	}{
		{
			name: "result found and scan complete",
			fields: fields{Results: map[string]VulnerabilityResult{
				"test1": {
					ScanID:     "test1",
					IsComplete: true,
					Result: &harbor.VulnerabilityReport{
						GeneratedAt: testTime,
						Artifact: harbor.Artifact{
							Repository: "test",
							Digest:     "testdigest",
							Tag:        "1.0.0",
						},
						Scanner: harbor.Scanner{
							Name:    "testScanner",
							Vendor:  "vendor1",
							Version: "1.0.0",
						},
						Severity: harbor.SevCritical,
						Vulnerabilities: []harbor.VulnerableItem{
							{
								ID:          "CVE-1234",
								Severity:    harbor.SevCritical,
								Pkg:         "testPkg",
								Version:     "1.0.0",
								Description: "testDescription",
								Links:       []string{"testLink"},
								Fixed:       "1.0.1",
							},
						},
					},
				},
			}},
			args: args{
				scanID: "test1",
				buildFn: func() (*harbor.VulnerabilityReport, error) {
					return &harbor.VulnerabilityReport{}, nil
				},
			},
			want: VulnerabilityResult{
				ScanID:     "test1",
				IsComplete: true,
				Result: &harbor.VulnerabilityReport{
					GeneratedAt: testTime,
					Artifact: harbor.Artifact{
						Repository: "test",
						Digest:     "testdigest",
						Tag:        "1.0.0",
					},
					Scanner: harbor.Scanner{
						Name:    "testScanner",
						Vendor:  "vendor1",
						Version: "1.0.0",
					},
					Severity: harbor.SevCritical,
					Vulnerabilities: []harbor.VulnerableItem{
						{
							ID:          "CVE-1234",
							Severity:    harbor.SevCritical,
							Pkg:         "testPkg",
							Version:     "1.0.0",
							Description: "testDescription",
							Links:       []string{"testLink"},
							Fixed:       "1.0.1",
						},
					},
				},
			},
			wantResponseOnChannel: false,
		},
		{
			name: "result found and scan incomplete",
			fields: fields{Results: map[string]VulnerabilityResult{
				"test1": {
					ScanID:     "test1",
					IsComplete: false,
				},
			}},
			args: args{
				scanID: "test1",
				buildFn: func() (*harbor.VulnerabilityReport, error) {
					return &harbor.VulnerabilityReport{}, nil
				},
			},
			want: VulnerabilityResult{
				ScanID:     "test1",
				IsComplete: false,
				Result:     nil,
			},
			wantResponseOnChannel: false,
		},
		{
			name:   "error in build function",
			fields: fields{Results: map[string]VulnerabilityResult{}},
			args: args{
				scanID: "test1",
				buildFn: func() (*harbor.VulnerabilityReport, error) {
					return &harbor.VulnerabilityReport{}, fmt.Errorf("test error")
				},
			},
			want: VulnerabilityResult{
				ScanID:     "test1",
				IsComplete: false,
				Result:     nil,
			},
			wantResponseOnChannel: true,
			wantErr:               true,
			wantChannelResult: VulnerabilityResult{
				ScanID:     "test1",
				IsComplete: true,
				Result:     nil,
				Error:      fmt.Errorf("test error"),
			},
		},
		{
			name:   "result not found",
			fields: fields{Results: map[string]VulnerabilityResult{}},
			args: args{
				scanID: "test1",
				buildFn: func() (*harbor.VulnerabilityReport, error) {
					return &harbor.VulnerabilityReport{
						GeneratedAt: testTime,
						Artifact: harbor.Artifact{
							Repository: "test",
							Digest:     "testdigest",
							Tag:        "1.0.0",
						},
						Scanner: harbor.Scanner{
							Name:    "testScanner",
							Vendor:  "vendor1",
							Version: "1.0.0",
						},
						Severity: harbor.SevCritical,
						Vulnerabilities: []harbor.VulnerableItem{
							{
								ID:          "CVE-1234",
								Severity:    harbor.SevCritical,
								Pkg:         "testPkg",
								Version:     "1.0.0",
								Description: "testDescription",
								Links:       []string{"testLink"},
								Fixed:       "1.0.1",
							},
						},
					}, nil
				},
			},
			want: VulnerabilityResult{
				ScanID:     "test1",
				IsComplete: false,
				Result:     nil,
				Error:      fmt.Errorf("result not ready"),
			},
			wantResponseOnChannel: true,
			wantErr:               true,
			wantChannelResult: VulnerabilityResult{
				ScanID:     "test1",
				IsComplete: true,
				Result: &harbor.VulnerabilityReport{
					GeneratedAt: testTime,
					Artifact: harbor.Artifact{
						Repository: "test",
						Digest:     "testdigest",
						Tag:        "1.0.0",
					},
					Scanner: harbor.Scanner{
						Name:    "testScanner",
						Vendor:  "vendor1",
						Version: "1.0.0",
					},
					Severity: harbor.SevCritical,
					Vulnerabilities: []harbor.VulnerableItem{
						{
							ID:          "CVE-1234",
							Severity:    harbor.SevCritical,
							Pkg:         "testPkg",
							Version:     "1.0.0",
							Description: "testDescription",
							Links:       []string{"testLink"},
							Fixed:       "1.0.1",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MemoryResultStore{
				Results: tt.fields.Results,
			}
			got := m.RequestResult(tt.args.scanID, tt.args.buildFn)
			if tt.wantErr {
				assert.Error(t, got.Error)
			} else {
				assert.NoError(t, got.Error)
				assert.Equal(t, tt.want, got)
			}
			if tt.wantResponseOnChannel {
				assert.Equal(t, tt.wantChannelResult, <-resultChannel)
			}
		})
	}
}
