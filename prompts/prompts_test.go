package prompts

import (
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/spectrocloud-labs/prompts-tui/prompts/mocks"
)

func TestReadBool(t *testing.T) {
	subtests := []struct {
		name         string
		tui          *mocks.MockTUI
		defaultVal   bool
		expectedData bool
		expectedErr  error
	}{
		{
			name: "Read Yes (lower)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"y"},
				Errs:       nil,
			},
			expectedData: true,
			expectedErr:  nil,
		},
		{
			name: "Read Yes (upper)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"Y"},
				Errs:       nil,
			},
			expectedData: true,
			expectedErr:  nil,
		},
		{
			name: "Read No (lower)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"n"},
				Errs:       nil,
			},
			expectedData: false,
			expectedErr:  nil,
		},
		{
			name: "Read No (upper)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"N"},
				Errs:       nil,
			},
			expectedData: false,
			expectedErr:  nil,
		},
		{
			name: "Read Default (true)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{""},
				Errs:       nil,
			},
			defaultVal:   true,
			expectedData: true,
			expectedErr:  nil,
		},
		{
			name: "Read Default (false)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{""},
				Errs:       nil,
			},
			defaultVal:   false,
			expectedData: false,
			expectedErr:  nil,
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			Tui = subtest.tui

			data, err := ReadBool("", subtest.defaultVal)
			if !reflect.DeepEqual(data, subtest.expectedData) {
				t.Errorf("expected (%t), got (%t)", subtest.expectedData, data)
			}
			if err != nil && err.Error() != subtest.expectedErr.Error() {
				t.Errorf("expected error (%v), got error (%v)", subtest.expectedErr, err)
			}
		})
	}
}

func TestReadInt(t *testing.T) {
	subtests := []struct {
		name         string
		tui          *mocks.MockTUI
		min          int
		max          int
		expectedData int
		expectedErr  error
	}{
		{
			name: "Read Int (pass)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"1"},
				Errs:       nil,
			},
			expectedData: 1,
			expectedErr:  nil,
		},
		{
			name: "Read Int (fail)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"2"},
				Errs:       []error{errors.New("fail")},
			},
			expectedData: -1,
			expectedErr:  errors.New("failure in ReadInt: fail"),
		},
		{
			name: "Read Int (fail_min)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"2"},
				Errs:       nil,
			},
			min:          10,
			expectedData: -1,
			expectedErr:  errors.New("failure in ReadInt: minimum is 10"),
		},
		{
			name: "Read Int (fail_max)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"2"},
				Errs:       nil,
			},
			max:          1,
			expectedData: -1,
			expectedErr:  errors.New("failure in ReadInt: maximum is 1"),
		},
		{
			name: "Read Int (fail_extra)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"-1", "a"},
				Errs:       nil,
			},
			max:          1,
			expectedData: -1,
			expectedErr:  errors.New("failure in ReadInt: maximum is 1: strconv.ParseInt: parsing \"a\": invalid syntax"),
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			Tui = subtest.tui

			data, err := ReadInt("", "", subtest.min, subtest.max)
			if !reflect.DeepEqual(data, subtest.expectedData) {
				t.Errorf("expected (%d), got (%d)", subtest.expectedData, data)
			}
			if err != nil && err.Error() != subtest.expectedErr.Error() {
				t.Errorf("expected error (%v), got error (%v)", subtest.expectedErr, err)
			}
		})
	}
}

func TestReadText(t *testing.T) {
	subtests := []struct {
		name         string
		tui          *mocks.MockTUI
		isOptional   bool
		maxLen       int
		expectedData string
		expectedErr  error
	}{
		{
			name: "Read Text (pass)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo"},
				Errs:       nil,
			},
			expectedData: "foo",
			expectedErr:  nil,
		},
		{
			name: "Read Text (fail)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo"},
				Errs:       []error{errors.New("fail")},
			},
			expectedData: "foo",
			expectedErr:  errors.New("failure in ReadText: fail"),
		},
		{
			name: "Read Text (fail_len)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo"},
				Errs:       nil,
			},
			maxLen:       2,
			expectedData: "foo",
			expectedErr:  errors.New("failure in ReadText: maximum length of 2 chars exceeded. input length: 3"),
		},
		{
			name: "Read Text (fail_optional)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{""},
				Errs:       nil,
			},
			isOptional:   false,
			expectedData: "",
			expectedErr:  errors.New("failure in ReadText: input is mandatory"),
		},
		{
			name: "Read Text (fail_extra)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"", ""},
				Errs:       []error{errors.New("fail")},
			},
			isOptional:   true,
			expectedData: "",
			expectedErr:  errors.New("failure in ReadText: fail"),
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			Tui = subtest.tui

			data, err := ReadText("", "", subtest.isOptional, subtest.maxLen)
			if !reflect.DeepEqual(data, subtest.expectedData) {
				t.Errorf("expected (%s), got (%s)", subtest.expectedData, data)
			}
			if err != nil && err.Error() != subtest.expectedErr.Error() {
				t.Errorf("expected error (%v), got error (%v)", subtest.expectedErr, err)
			}
		})
	}
}

func TestReadDomains(t *testing.T) {
	subtests := []struct {
		name         string
		tui          *mocks.MockTUI
		errMsg       string
		isOptional   bool
		maxVals      int
		expectedData string
		expectedErr  error
	}{
		{
			name: "ReadDomains (pass_spectro)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"spectrocloud.dev"},
			},
			maxVals:      1,
			expectedData: "spectrocloud.dev",
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			Tui = subtest.tui

			data, err := ReadDomains("", "", subtest.errMsg, subtest.isOptional, subtest.maxVals)
			if !reflect.DeepEqual(data, subtest.expectedData) {
				t.Errorf("expected (%s), got (%s)", subtest.expectedData, data)
			}
			if err != nil && err.Error() != subtest.expectedErr.Error() {
				t.Errorf("expected error (%v), got error (%v)", subtest.expectedErr, err)
			}
		})
	}
}

func TestReadDomainsOrIPs(t *testing.T) {
	subtests := []struct {
		name         string
		tui          *mocks.MockTUI
		errMsg       string
		isOptional   bool
		maxVals      int
		expectedData string
		expectedErr  error
	}{
		{
			name: "ReadDomainsOrIPs (IP pass)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"10.10.10.10"},
			},
			maxVals:      1,
			expectedData: "10.10.10.10",
		},
		{
			name: "ReadDomainsOrIPs (IP fail)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"10.10.10.10.10"},
				Errs:       []error{errors.New("fail")},
			},
			maxVals:      1,
			expectedData: "10.10.10.10.10",
			expectedErr:  errors.New("failure in ReadDomainsOrIPs: fail"),
		},
		{
			name: "ReadDomainsOrIPs (Domain pass basic)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"vcenter.spectrocloud.dev"},
			},
			maxVals:      1,
			expectedData: "vcenter.spectrocloud.dev",
		},
		{
			name: "ReadDomainsOrIPs (Domain pass long)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"0.lab.vcenter.spectrocloud.dev"},
			},
			maxVals:      1,
			expectedData: "0.lab.vcenter.spectrocloud.dev",
		},
		{
			name: "ReadDomainsOrIPs (Domain pass long with dashes)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"0.lab.v-center.spectro-cloud.dev"},
			},
			maxVals:      1,
			expectedData: "0.lab.v-center.spectro-cloud.dev",
		},
		{
			name: "ReadDomainsOrIPs (Domain pass short)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"to.io"},
			},
			maxVals:      1,
			expectedData: "to.io",
		},
		{
			name: "ReadDomainsOrIPs (Domain pass dashes)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"ps-vcenter-02.ps.labs.local"},
			},
			maxVals:      1,
			expectedData: "ps-vcenter-02.ps.labs.local",
		},
		{
			name: "ReadDomainsOrIPs (Domain pass multiple sub-domains)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"vcenter.spectrocloud.foo.bar.baz.dev"},
			},
			maxVals:      1,
			expectedData: "vcenter.spectrocloud.foo.bar.baz.dev",
		},
		{
			name: "ReadDomainsOrIPs (Domain fail leading dash)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"-vcenter.spectrocloud.dev"},
				Errs:       []error{errors.New("fail")},
			},
			maxVals:      1,
			errMsg:       "invalid domain",
			expectedData: "-vcenter.spectrocloud.dev",
			expectedErr:  errors.New("failure in ReadDomainsOrIPs: invalid domain: -vcenter.spectrocloud.dev is neither an IP, IP:port, or an FQDN"),
		},
		{
			name: "ReadDomainsOrIPs (Domain fail trailing dash)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"vcenter.spectrocloud.dev-"},
				Errs:       []error{errors.New("fail")},
			},
			maxVals:      1,
			errMsg:       "invalid domain",
			expectedData: "vcenter.spectrocloud.dev-",
			expectedErr:  errors.New("failure in ReadDomainsOrIPs: invalid domain: vcenter.spectrocloud.dev- is neither an IP, IP:port, or an FQDN"),
		},
		{
			name: "ReadDomainsOrIPs (Domain fail consecutive dashes)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"vcenter.spectro--cloud.dev"},
				Errs:       []error{errors.New("fail")},
			},
			maxVals:      1,
			errMsg:       "invalid domain",
			expectedData: "vcenter.spectro--cloud.dev",
			expectedErr:  errors.New("failure in ReadDomainsOrIPs: invalid domain: vcenter.spectro--cloud.dev is neither an IP, IP:port, or an FQDN"),
		},
		{
			name: "ReadDomainsOrIPs (Domain fail dot dash)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"vcenter.-spectrocloud.dev"},
				Errs:       []error{errors.New("fail")},
			},
			maxVals:      1,
			errMsg:       "invalid domain",
			expectedData: "vcenter.-spectrocloud.dev",
			expectedErr:  errors.New("failure in ReadDomainsOrIPs: invalid domain: vcenter.-spectrocloud.dev is neither an IP, IP:port, or an FQDN"),
		},
		{
			name: "ReadDomainsOrIPs (Domain fail dash dot)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"vcenter-.spectrocloud.dev"},
				Errs:       []error{errors.New("fail")},
			},
			maxVals:      1,
			errMsg:       "invalid domain",
			expectedData: "vcenter-.spectrocloud.dev",
			expectedErr:  errors.New("failure in ReadDomainsOrIPs: invalid domain: vcenter-.spectrocloud.dev is neither an IP, IP:port, or an FQDN"),
		},
		{
			name: "ReadDomainsOrIPs (Domain fail invalid char)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"vcenter.spectro*cloud.dev"},
				Errs:       []error{errors.New("fail")},
			},
			maxVals:      1,
			errMsg:       "invalid domain",
			expectedData: "vcenter.spectro*cloud.dev",
			expectedErr:  errors.New("failure in ReadDomainsOrIPs: invalid domain: vcenter.spectro*cloud.dev is neither an IP, IP:port, or an FQDN"),
		},
		{
			name: "ReadDomainsOrIPs (fail_optional)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{""},
			},
			maxVals:      1,
			isOptional:   false,
			errMsg:       InputMandatoryError.Error(),
			expectedData: "",
			expectedErr:  errors.New("failure in ReadDomainsOrIPs: input is mandatory"),
		},
		{
			name: "ReadDomainsOrIPs (pass_max_vals)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo.com,bar.io,baz.ca"},
			},
			maxVals:      3,
			isOptional:   false,
			expectedData: "foo.com,bar.io,baz.ca",
		},
		{
			name: "ReadDomainsOrIPs (fail_max_vals)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo.com,bar.io"},
			},
			maxVals:      1,
			isOptional:   false,
			errMsg:       "invalid domains or IPs",
			expectedData: "foo.com,bar.io",
			expectedErr:  errors.New("failure in ReadDomainsOrIPs: invalid domains or IPs: maximum domains or IPs: 1"),
		},
		{
			name: "ReadDomainsOrIPs (fail_extra)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"", ""},
				Errs:       []error{errors.New("fail")},
			},
			isOptional:  true,
			maxVals:     1,
			expectedErr: errors.New("failure in ReadDomainsOrIPs: fail"),
		},
		{
			name: "ReadDomainsOrIPs (pass_spectro)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"spectrocloud.dev"},
			},
			maxVals:      1,
			expectedData: "spectrocloud.dev",
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			Tui = subtest.tui

			data, err := ReadDomainsOrIPs("", "", subtest.errMsg, subtest.isOptional, subtest.maxVals)
			if !reflect.DeepEqual(data, subtest.expectedData) {
				t.Errorf("expected (%s), got (%s)", subtest.expectedData, data)
			}
			if err != nil && err.Error() != subtest.expectedErr.Error() {
				t.Errorf("expected error (%v), got error (%v)", subtest.expectedErr, err)
			}
		})
	}
}

func TestReadNoProxy(t *testing.T) {
	defaultNoProxy := "127.0.0.1,192.168.0.0/16,10.0.0.0/16,10.96.0.0/12,169.254.169.254,169.254.0.0/24,localhost,kubernetes,kubernetes.default,kubernetes.default.svc,kubernetes.default.svc.cluster,kubernetes.default.svc.cluster.local,.svc,.svc.cluster,.svc.cluster.local,.svc.cluster.local,.company.local"
	validate := func(s string) error {
		for _, x := range strings.Split(s, ",") {
			if err := ValidateNoProxy(x); err != nil {
				return err
			}
		}
		return nil
	}
	subtests := []struct {
		name         string
		tui          *mocks.MockTUI
		isOptional   bool
		expectedData string
		expectedErr  error
	}{
		{
			name: "Read No Proxy (pass DefaultNoProxy)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{defaultNoProxy},
			},
			expectedData: defaultNoProxy,
		},
		{
			name: "Read No Proxy (pass IP)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"10.10.10.10"},
			},
			expectedData: "10.10.10.10",
		},
		{
			name: "Read No Proxy (pass IP port)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"10.10.10.10:80"},
			},
			expectedData: "10.10.10.10:80",
		},
		{
			name: "Read No Proxy (pass CIDR)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"10.10.10.10/24"},
			},
			expectedData: "10.10.10.10/24",
		},
		{
			name: "Read No Proxy (pass domain w/ leading period)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{".vcenter.spectrocloud.dev"},
			},
			expectedData: ".vcenter.spectrocloud.dev",
		},
		{
			name: "Read No Proxy (pass exception)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"localhost"},
			},
			expectedData: "localhost",
		},
		{
			name: "Read No Proxy (fail_validation)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"abc"},
				Errs:       []error{errors.New("fail")},
			},
			expectedData: "abc",
			expectedErr:  ValidationError,
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			Tui = subtest.tui
			data, err := Tui.GetText("", "", "", subtest.isOptional, validate)
			if !reflect.DeepEqual(data, subtest.expectedData) {
				t.Errorf("expected (%s), got (%s)", subtest.expectedData, data)
			}
			if err != nil && err.Error() != subtest.expectedErr.Error() {
				t.Errorf("expected error (%v), got error (%v)", subtest.expectedErr, err)
			}
		})
	}
}

func TestReadK8sName(t *testing.T) {
	subtests := []struct {
		name         string
		tui          *mocks.MockTUI
		errMsg       string
		isOptional   bool
		expectedData string
		expectedErr  error
	}{
		{
			name: "Read K8sName (pass)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo"},
				Errs:       nil,
			},
			expectedData: "foo",
			expectedErr:  nil,
		},
		{
			name: "Read K8sName (fail)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo"},
				Errs:       []error{errors.New("fail")},
			},
			expectedData: "foo",
			expectedErr:  errors.New("failure in ReadK8sName: fail"),
		},
		{
			name: "Read K8sName (fail_name)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{".invalidName"},
				Errs:       nil,
			},
			expectedData: ".invalidName",
			expectedErr:  errors.New("failure in ReadK8sName: name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')"),
		},
		{
			name: "Read K8sName (fail_name2)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"UPPER"},
				Errs:       nil,
			},
			expectedData: "UPPER",
			expectedErr:  errors.New("failure in ReadK8sName: a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')"),
		},
		{
			name: "Read K8sName (fail_len)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"aaaaaaaaaa-aaaaaaaaaa-aaaaaaaaaa-aaaaaaaaaa-aaaaaaaaaa-aaaaaaaaaa"},
				Errs:       nil,
			},
			expectedData: "aaaaaaaaaa-aaaaaaaaaa-aaaaaaaaaa-aaaaaaaaaa-aaaaaaaaaa-aaaaaaaaaa",
			expectedErr:  errors.New("failure in ReadK8sName: name part must be no more than 63 characters"),
		},
		{
			name: "Read K8sName (optional_not_provided)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{""},
				Errs:       nil,
			},
			isOptional:   true,
			expectedData: "",
			expectedErr:  nil,
		},
		{
			name: "Read K8sName (fail_optional)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{""},
				Errs:       nil,
			},
			isOptional:   false,
			errMsg:       InputMandatoryError.Error(),
			expectedData: "",
			expectedErr:  errors.New("failure in ReadK8sName: input is mandatory"),
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			Tui = subtest.tui

			data, err := ReadK8sName("", "", subtest.isOptional)
			if !reflect.DeepEqual(data, subtest.expectedData) {
				t.Errorf("expected (%s), got (%s)", subtest.expectedData, data)
			}
			if err != nil && err.Error() != subtest.expectedErr.Error() {
				t.Errorf("expected error (%v), got error (%v)", subtest.expectedErr, err)
			}
		})
	}
}

func TestReadPassword(t *testing.T) {
	subtests := []struct {
		name         string
		tui          *mocks.MockTUI
		errMsg       string
		isOptional   bool
		maxLen       int
		expectedData string
		expectedErr  error
	}{
		{
			name: "Read Password (pass)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo"},
				Errs:       nil,
			},
			expectedData: "foo",
			expectedErr:  nil,
		},
		{
			name: "Read Password (fail)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo"},
				Errs:       []error{errors.New("fail")},
			},
			expectedData: "foo",
			expectedErr:  errors.New("failure in ReadPassword: fail"),
		},
		{
			name: "Read Password (fail_len)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo"},
				Errs:       nil,
			},
			maxLen:       2,
			expectedData: "foo",
			expectedErr:  errors.New("failure in ReadPassword: maximum length of 2 chars exceeded. input length: 3"),
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			Tui = subtest.tui

			data, err := ReadPassword("", "", subtest.isOptional, subtest.maxLen)
			if !reflect.DeepEqual(data, subtest.expectedData) {
				t.Errorf("expected (%s), got (%s)", subtest.expectedData, data)
			}
			if err != nil && err.Error() != subtest.expectedErr.Error() {
				t.Errorf("expected error (%v), got error (%v)", subtest.expectedErr, err)
			}
		})
	}
}

func TestSemVer(t *testing.T) {
	subtests := []struct {
		name         string
		tui          *mocks.MockTUI
		errMsg       string
		expectedData string
		expectedErr  error
	}{
		{
			name: "ReadSemVer (fail)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"0.0.1"},
				Errs:       []error{errors.New("fail")},
			},
			errMsg:       "invalid Helm chart version",
			expectedData: "0.0.1",
			expectedErr:  errors.New("failure in ReadSemVer: input 0.0.1 must start with a 'v'; invalid Helm chart version"),
		},
		{
			name: "ReadSemVer (pass)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"v0.0.1"},
				Errs:       nil,
			},
			expectedData: "v0.0.1",
			expectedErr:  nil,
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			Tui = subtest.tui

			data, err := ReadSemVer("", "", subtest.errMsg)
			if !reflect.DeepEqual(data, subtest.expectedData) {
				t.Errorf("expected (%s), got (%s)", subtest.expectedData, data)
			}
			if err != nil && err.Error() != subtest.expectedErr.Error() {
				t.Errorf("expected error (%v), got error (%v)", subtest.expectedErr, err)
			}
		})
	}
}

func TestReadTextRegex(t *testing.T) {
	subtests := []struct {
		name         string
		tui          *mocks.MockTUI
		errMsg       string
		regexPattern string
		expectedData string
		expectedErr  error
	}{
		{
			name: "Read TextRegex (pass)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo"},
				Errs:       nil,
			},
			regexPattern: KindClusterRegex,
			expectedData: "foo",
			expectedErr:  nil,
		},
		{
			name: "Read TextRegex (fail)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo"},
				Errs:       []error{errors.New("fail")},
			},
			regexPattern: KindClusterRegex,
			expectedData: "foo",
			expectedErr:  errors.New("failure in ReadTextRegex: fail"),
		},
		{
			name: "Read TextRegex (fail_regex)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo@"},
				Errs:       nil,
			},
			regexPattern: KindClusterRegex,
			expectedData: "foo@",
			errMsg:       "error",
			expectedErr:  errors.New("failure in ReadTextRegex: input foo@ does not match regex ^[a-z0-9]{1}[a-z0-9-]{0,30}[a-z0-9]{1}$; error"),
		},
		{
			name: "Read TextRegex (fail_regex_long)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"fffffffffffffffffffffffffffffffff"},
				Errs:       nil,
			},
			regexPattern: KindClusterRegex,
			expectedData: "fffffffffffffffffffffffffffffffff",
			errMsg:       "error",
			expectedErr:  errors.New("failure in ReadTextRegex: input fffffffffffffffffffffffffffffffff does not match regex ^[a-z0-9]{1}[a-z0-9-]{0,30}[a-z0-9]{1}$; error"),
		},
		{
			name: "Read TextRegex (fail_regex_first_char_alpha)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"-ff"},
				Errs:       nil,
			},
			regexPattern: KindClusterRegex,
			expectedData: "-ff",
			errMsg:       "error",
			expectedErr:  errors.New("failure in ReadTextRegex: input -ff does not match regex ^[a-z0-9]{1}[a-z0-9-]{0,30}[a-z0-9]{1}$; error"),
		},
		{
			name: "Read TextRegex (fail_regex_last_char_alpha)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"ff-"},
				Errs:       nil,
			},
			regexPattern: KindClusterRegex,
			expectedData: "ff-",
			errMsg:       "error",
			expectedErr:  errors.New("failure in ReadTextRegex: input ff- does not match regex ^[a-z0-9]{1}[a-z0-9-]{0,30}[a-z0-9]{1}$; error"),
		},
		{
			name: "Read TextRegex (fail_regex_short)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"f"},
				Errs:       nil,
			},
			regexPattern: KindClusterRegex,
			expectedData: "f",
			errMsg:       "error",
			expectedErr:  errors.New("failure in ReadTextRegex: input f does not match regex ^[a-z0-9]{1}[a-z0-9-]{0,30}[a-z0-9]{1}$; error"),
		},
		{
			name: "Read TextRegex (invalid_regex)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"abc"},
				Errs:       nil,
			},
			regexPattern: "?!",
			errMsg:       "fail",
			expectedData: "abc",
			expectedErr:  errors.New("failure in ReadTextRegex: fail: error parsing regexp: missing argument to repetition operator: `?`"),
		},
		{
			name: "Read TextRegex (invalid_input)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{""},
				Errs:       nil,
			},
			regexPattern: "",
			expectedData: "",
			expectedErr:  errors.New("failure in ReadTextRegex: input is mandatory"),
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			Tui = subtest.tui

			data, err := ReadTextRegex("", "", subtest.errMsg, subtest.regexPattern)
			if !reflect.DeepEqual(data, subtest.expectedData) {
				t.Errorf("expected (%s), got (%s)", subtest.expectedData, data)
			}
			if err != nil && err.Error() != subtest.expectedErr.Error() {
				t.Errorf("expected error (%v), got error (%v)", subtest.expectedErr, err)
			}
		})
	}
}

func TestReadURLRegex(t *testing.T) {
	MaasApiRegex := "^.*\\/MAAS$"

	subtests := []struct {
		name         string
		tui          *mocks.MockTUI
		errMsg       string
		regexPattern string
		expectedData string
		expectedErr  error
	}{
		{
			name: "ReadURLRegex (pass)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"https://company-maas.com/MAAS"},
				Errs:       nil,
			},
			regexPattern: MaasApiRegex,
			expectedData: "https://company-maas.com/MAAS",
			expectedErr:  nil,
		},
		{
			name: "ReadURLRegex (fail)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo"},
				Errs:       []error{errors.New("fail")},
			},
			regexPattern: MaasApiRegex,
			errMsg:       "invalid MAAS URL",
			expectedData: "foo",
			expectedErr:  errors.New("failure in ReadURLRegex: input foo does not match regex ^.*\\/MAAS$; invalid MAAS URL"),
		},
		{
			name: "ReadURLRegex (fail_url)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"company-maas.com/MAAS"},
			},
			regexPattern: MaasApiRegex,
			expectedData: "company-maas.com/MAAS",
			errMsg:       "fail",
			expectedErr:  errors.New("failure in ReadURLRegex: fail: parse \"company-maas.com/MAAS\": invalid URI for request"),
		},
		{
			name: "ReadURLRegex (fail_regex)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo@"},
				Errs:       nil,
			},
			regexPattern: MaasApiRegex,
			errMsg:       "error",
			expectedData: "foo@",
			expectedErr:  errors.New("failure in ReadURLRegex: input foo@ does not match regex ^.*\\/MAAS$; error"),
		},
		{
			name: "ReadURLRegex (invalid_regex)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"abc"},
				Errs:       nil,
			},
			regexPattern: "?!",
			errMsg:       "fail",
			expectedData: "abc",
			expectedErr:  errors.New("failure in ReadURLRegex: fail: error parsing regexp: missing argument to repetition operator: `?`"),
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			Tui = subtest.tui

			data, err := ReadURLRegex("", "", subtest.errMsg, subtest.regexPattern)
			if !reflect.DeepEqual(data, subtest.expectedData) {
				t.Errorf("expected (%s), got (%s)", subtest.expectedData, data)
			}
			if err != nil && err.Error() != subtest.expectedErr.Error() {
				t.Errorf("expected error (%v), got error (%v)", subtest.expectedErr, err)
			}
		})
	}
}

func TestSelect(t *testing.T) {
	subtests := []struct {
		name         string
		tui          *mocks.MockTUI
		expectedData string
		expectedErr  error
	}{
		{
			name: "Select (pass)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo"},
				Errs:       nil,
			},
			expectedData: "foo",
			expectedErr:  nil,
		},
		{
			name: "Select (fail)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"foo"},
				Errs:       []error{errors.New("fail")},
			},
			expectedData: "",
			expectedErr:  errors.New("failure in Select: fail"),
		},
		{
			name: "Select (fail_no_items)",
			tui: &mocks.MockTUI{
				Errs: []error{errors.New("failure in Select: no options available: Select (fail_no_items)")},
			},
			expectedData: "",
			expectedErr:  errors.New("failure in Select: no options available: Select (fail_no_items)"),
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			Tui = subtest.tui

			data, err := Select(subtest.name, subtest.tui.ReturnVals)
			if !reflect.DeepEqual(data, subtest.expectedData) {
				t.Errorf("expected (%s), got (%s)", subtest.expectedData, data)
			}
			if err != nil && err.Error() != subtest.expectedErr.Error() {
				t.Errorf("expected error (%v), got error (%v)", subtest.expectedErr, err)
			}
		})
	}
}

func TestSelectID(t *testing.T) {
	zero := &ChoiceItem{ID: "0", Name: "zero"}
	options := []ChoiceItem{*zero}

	subtests := []struct {
		name         string
		tui          *mocks.MockTUI
		options      []ChoiceItem
		expectedData *ChoiceItem
		expectedErr  error
	}{
		{
			name: "SelectID (pass)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"zero"},
				Errs:       nil,
			},
			options:      options,
			expectedData: zero,
			expectedErr:  nil,
		},
		{
			name: "SelectID (fail)",
			tui: &mocks.MockTUI{
				ReturnVals: []string{"zero"},
				Errs:       []error{errors.New("fail")},
			},
			options:      options,
			expectedData: nil,
			expectedErr:  errors.New("failure in SelectID: fail"),
		},
		{
			name: "SelectID (fail_no_items)",
			tui: &mocks.MockTUI{
				Errs: []error{errors.New("failure in SelectID: no options available: SelectID (fail_no_items)")},
			},
			expectedData: nil,
			expectedErr:  errors.New("failure in SelectID: no options available: SelectID (fail_no_items)"),
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			Tui = subtest.tui

			data, err := SelectID(subtest.name, subtest.options)
			if !reflect.DeepEqual(data, subtest.expectedData) {
				t.Errorf("expected (%s), got (%s)", subtest.expectedData, data)
			}
			if err != nil && err.Error() != subtest.expectedErr.Error() {
				t.Errorf("expected error (%v), got error (%v)", subtest.expectedErr, err)
			}
		})
	}
}

func TestValidateNoProxy(t *testing.T) {
	subtests := []struct {
		name        string
		noProxy     string
		expectedErr error
	}{
		{
			name:        "ValidateNoProxy (empty_string)",
			noProxy:     "",
			expectedErr: nil,
		},
		{
			name:        "ValidateNoProxy (pass_default)",
			noProxy:     "127.0.0.1,192.168.0.0/16,10.0.0.0/16,10.96.0.0/12,169.254.169.254,169.254.0.0/24,localhost,kubernetes,kubernetes.default,kubernetes.default.svc,kubernetes.default.svc.cluster,kubernetes.default.svc.cluster.local,.svc,.svc.cluster,.svc.cluster.local,.svc.cluster.local,.company.local",
			expectedErr: nil,
		},
		{
			name:        "ValidateNoProxy (fail)",
			noProxy:     "notanoproxy",
			expectedErr: ValidationError,
		},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			for _, s := range strings.Split(subtest.noProxy, ",") {
				err := ValidateNoProxy(s)
				if err != nil && err.Error() != subtest.expectedErr.Error() {
					t.Errorf("expected error (%v), got error (%v)", subtest.expectedErr, err)
				}
			}
		})
	}
}

func TestArtifactRefRegex(t *testing.T) {
	regex := regexp.MustCompile(ArtifactRefRegex)

	testCases := []struct {
		input         string
		expectedMatch bool
	}{
		{
			input:         "valid/digest/artifact/path@sha256:abcdef",
			expectedMatch: true,
		},
		{
			input:         "valid/tag/artifact/path:v1.0.0",
			expectedMatch: true,
		},
		{
			input:         "valid/no/tag/or/digest",
			expectedMatch: true,
		},
		{
			input:         "Invalid/Path/To/Artifact",
			expectedMatch: false,
		},
		{
			input:         "invalid/digest/artifact/path@sha253:abcdef",
			expectedMatch: false,
		},
	}

	for _, tc := range testCases {
		actual := regex.MatchString(tc.input)
		if actual != tc.expectedMatch {
			t.Errorf("input: %s, expected: %v, actual: %v", tc.input, tc.expectedMatch, actual)
		}
	}
}

func TestValidateJson(t *testing.T) {
	subtests := []struct {
		name        string
		json        string
		expectedErr error
	}{
		{
			name:        "ValidateJson (empty_string)",
			json:        "",
			expectedErr: nil,
		},
		{
			name:        "ValidateJson (pass)",
			json:        `{"key": "value"}`,
			expectedErr: nil,
		},
		{
			name:        "ValidateJson (fail)",
			json:        `{"key": "value"`,
			expectedErr: ValidationError,
		},
	}

	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			err := ValidateJson(subtest.json)
			if err != nil && err.Error() != subtest.expectedErr.Error() {
				t.Errorf("expected error (%v), got error (%v)", subtest.expectedErr, err)
			}
		})
	}
}

func TestValidateSSHPublicKey(t *testing.T) {
	subtests := []struct {
		name        string
		sshKey      string
		expectedErr error
	}{
		{
			name:        "ValidateSSHPublicKey (empty_string)",
			sshKey:      "",
			expectedErr: nil,
		},
		{
			name:        "ValidateSSHPublicKey (pass)",
			sshKey:      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEIrPZHAGI+sCM79NFrSxHTU8A32OtjoNFz3s7+JwDOG",
			expectedErr: nil,
		},
		{
			name:        "ValidateSSHPublicKey (fail)",
			sshKey:      "ssh-ed25519 invalid",
			expectedErr: ValidationError,
		},
	}

	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			err := ValidateSSHPublicKey(subtest.sshKey)
			if err != nil && err.Error() != subtest.expectedErr.Error() {
				t.Errorf("expected error (%v), got error (%v)", subtest.expectedErr, err)
			}
		})
	}
}
