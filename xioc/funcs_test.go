package xioc

import (
	"encoding/json"
	"os"
	"testing"
)

func contains(arr []string, s string) bool {
	for _, v := range arr {
		if v == s {
			return true
		}
	}
	return false
}

func testHelper(t *testing.T, testName string, extracted []string, expected []string) {
	t.Run(testName, func(t *testing.T) {
		if len(extracted) == 0 && len(expected) == 0 {
			return
		}

		for _, answer := range expected {
			if !contains(extracted, answer) {
				t.Fatalf(`"%s" should be in extracted: %v`, answer, extracted)
			}
		}

		for _, e := range extracted {
			if !contains(expected, e) {
				t.Fatalf(`"%s" extracted but not in expected: %v`, e, expected)
			}
		}
	})
}

func TestExtractAddress(t *testing.T) {
	var tests map[string]map[string][]string

	f, err := os.Open("tests.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	json.NewDecoder(f).Decode(&tests)

	testTypes := []string{"domains", "ip4s", "ip6s", "urls", "emails"}
	for input, expectedOutputs := range tests {
		for _, testType := range testTypes {
			var extracted []string
			if testType == "domains" {
				extracted = ExtractDomains(input)
			} else if testType == "ip4s" {
				extracted = ExtractIPv4s(input)
			} else if testType == "ip6s" {
				extracted = ExtractIPv6s(input)
			} else if testType == "urls" {
				extracted = ExtractURLs(input)
			} else if testType == "emails" {
				extracted = ExtractEmails(input)
			} else {
				t.Fatal("wat")
			}

			expected, ok := expectedOutputs[testType]
			if !ok {
				expected = []string{}
			}

			testHelper(t, testType+"=>"+input, extracted, expected)
		}
	}
}

func TestExtractHashes(t *testing.T) {
	tests := map[string]map[string][]string{
		"d41d8cd98f00b204e9800998ecf8427x": map[string][]string{
			"md5s":    []string{},
			"sha1s":   []string{},
			"sha256s": []string{},
		},
		"d41d8cd98f00b204e9800998ecf8427e": map[string][]string{
			"md5s":    []string{"d41d8cd98f00b204e9800998ecf8427e"},
			"sha1s":   []string{},
			"sha256s": []string{},
		},
		"da39a3ee5e6b4b0d3255bfef95601890afd80709": map[string][]string{
			"md5s":    []string{},
			"sha1s":   []string{"da39a3ee5e6b4b0d3255bfef95601890afd80709"},
			"sha256s": []string{},
		},
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": map[string][]string{
			"md5s":    []string{},
			"sha1s":   []string{},
			"sha256s": []string{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		},
	}

	testTypes := []string{"md5s", "sha1s", "sha256s"}
	for input, expectedOutputs := range tests {
		for _, testType := range testTypes {
			var extracted []string
			if testType == "md5s" {
				extracted = ExtractMD5s(input)
			} else if testType == "sha1s" {
				extracted = ExtractSHA1s(input)
			} else if testType == "sha256s" {
				extracted = ExtractSHA256s(input)
			} else {
				t.Fatal("wat")
			}

			expected, ok := expectedOutputs[testType]
			if !ok {
				expected = []string{}
			}
			testHelper(t, testType+"=>"+input, extracted, expected)
		}
	}
}

func TestExtractDefangedURLs(t *testing.T) {
	var urls = []struct {
		input       string
		expectedOut []string
	}{
		{"http://example.com", []string{}},
		{"http://example[.]com", []string{"http://example.com"}},
		{"http://example.com/someFile", []string{}},
		{"http://example[.]com/someFile", []string{"http://example.com/someFile"}},
		{"http://www15.youtube.com.silssl.com/watch.php?v=o8h2mD8b&c=SG&feature=youtu", []string{}},
		{"hxxp://example.com", []string{"http://example.com"}},
		{"hxxp://example[dot]com", []string{"http://example.com"}},
		{"http://legitURL.com someText hxxp://someMalware[.]com/exeuteme.exe", []string{"http://someMalware.com/exeuteme.exe"}},
		{"ftp://example.com", []string{}},
		{"ftp://example[.]com", []string{"ftp://example.com"}},
		{"invalid://example.com", []string{}},
		{"http://example[dot]com", []string{"http://example.com"}},
		{"hXXps://example[dot]com", []string{"https://example.com"}},
		{"https://unit42.paloaltonetworks.com/wp-content/plugins/recaptcha-in-wp-comments-form/js/base.js?ver=9.1.0'></script>", []string{}},
		{"https://unit42.paloaltonetworks[.]com/wp-content/plugins/recaptcha-in-wp-comments-form/js/base.js?ver=9.1.0'></script>", []string{"https://unit42.paloaltonetworks.com/wp-content/plugins/recaptcha-in-wp-comments-form/js/base.js?ver=9.1.0"}},
	}
	for _, tt := range urls {
		t.Run(tt.input, func(t *testing.T) {
			got := ExtractDefangedURLs(tt.input)
			// iterate over result slice
			for _, singleOutputURL := range tt.expectedOut {
				if stringInSlice(singleOutputURL, got) == false {
					t.Errorf("Found unexpected IOC. Input: %v, Output: %v, was expecting: %v", tt.input, got, tt.expectedOut)
				}
			}
		})
	}
}

func TestExtractDefangedDomains(t *testing.T) {
	var domains = []struct {
		input       string
		expectedOut []string
	}{
		{"http://example.com", []string{}},
		{"http://example[.]com", []string{"example.com"}},
		{"http://example.com/someFile", []string{}},
		{"http://example[.]com/someFile", []string{"example.com"}},
		{"http://www15.youtube.com.silssl.com/watch.php?v=o8h2mD8b&c=SG&feature=youtu", []string{}},
		{"hxxp://example.com", []string{}}, // only schema
		{"hxxp://example[dot]com", []string{"example.com"}},
		{"http://legitURL.com someText hxxp://someMalware[.]com/exeuteme.exe", []string{"somemalware.com"}},
		{"bob@acme.com", []string{}},
		{"https://unit42.paloaltonetworks.com/wp-content/plugins/recaptcha-in-wp-comments-form/js/base.js?ver=9.1.0'></script>", []string{}},
	}
	for _, tt := range domains {
		t.Run(tt.input, func(t *testing.T) {
			got := ExtractDefangedDomains(tt.input)
			// iterate over result slice
			for _, singleOutputDomain := range tt.expectedOut {
				if stringInSlice(singleOutputDomain, got) == false {
					t.Errorf("Found unexpected IOC. Input: %v, Output: %v, was expecting: %v", tt.input, got, tt.expectedOut)
				}
			}
		})
	}
}

func TestExtractDefangedEmails(t *testing.T) {
	var tests = []struct {
		input       string
		expectedOut []string
	}{
		{"someuser@hotmail.com", []string{}},
		{"someuser at hotmail.com", []string{"someuser@hotmail.com"}},
		{"someuser[@]hotmail.com", []string{"someuser@hotmail.com"}},
		{"someuser@hotmail[.]com", []string{"someuser@hotmail.com"}},
		{"send email to sales AT zimperium dot com", []string{"sales@zimperium.com"}},
		{"sales@zimperium.com", []string{}},
		{"user1 at hotmail dot com user2 at hotmail.com", []string{"user1@hotmail.com", "user2@hotmail.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ExtractDefangedEmails(tt.input)
			// iterate over result slice
			for _, singleEmail := range tt.expectedOut {
				if stringInSlice(singleEmail, got) == false {
					t.Errorf("Found unexpected IOC. Input: %v, Output: %v, was expecting: %v", tt.input, got, tt.expectedOut)
				}
			}
		})
	}
}

func TestExtractDefangedIPv4s(t *testing.T) {
	var ips = []struct {
		input       string
		expectedOut []string
	}{
		{"1.1.1.1", []string{}},
		{"1[.]1[.]1[.]1", []string{"1.1.1.1"}},
		{"1 dot 1 dot 1 dot 1", []string{"1.1.1.1"}},
		{"1.1.1.1000", []string{}},
		{"root@192.168.11.1", []string{}},
		{"1(dot)1(dot)1(dot)1", []string{"1.1.1.1"}},
	}
	for _, tt := range ips {
		t.Run(tt.input, func(t *testing.T) {
			got := ExtractDefangedIPv4s(tt.input)
			// iterate over result slice
			for _, singleIP := range tt.expectedOut {
				if stringInSlice(singleIP, got) == false {
					t.Errorf("Found unexpected IOC. Input: %v, Output: %v, was expecting: %v", tt.input, got, tt.expectedOut)
				}
			}
		})
	}
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
