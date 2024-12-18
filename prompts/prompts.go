// Package prompts contains helper functions for prompting users for input via the command line.
// It is a lightweight wrapper around the pterm library for writing text-based user interfaces.
package prompts

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"emperror.dev/errors"
	"github.com/Masterminds/semver"
	"github.com/pterm/pterm"
	"golang.org/x/crypto/ssh"
	"golang.org/x/exp/slices"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	// Adapted from: http://stackoverflow.com/questions/10306690/domain-name-validation-with-regex/26987741#26987741
	domain = "([a-zA-Z0-9]{1,63}|[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])(\\.[a-zA-Z0-9]{1,63}|\\.[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9]){0,10}\\.([a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]{0,30}[a-zA-Z0-9]\\.[a-zA-Z]{2,})"

	topLevelDomain = "\\.[a-zA-Z0-9][a-zA-Z0-9\\-_]{0,61}"

	// Adapted from: https://stackoverflow.com/a/36760050/7898074, https://stackoverflow.com/a/12968117/7898074
	ip   = "((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}"
	port = ":([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])"
)

var (
	// Tui is exported to enable monkey-patching.
	Tui TUI = PtermTUI{}

	// ErrValidationFailed is returned when input validation fails.
	ErrValidationFailed = errors.New("validation failed")

	// ErrInputMandatory is returned when mandatory input is missing.
	ErrInputMandatory = errors.New("input is mandatory")

	// Exported regex patterns for use with ReadTextRegex

	// KindClusterRegex is a regex pattern for validating a kind cluster name.
	KindClusterRegex = "^[a-z0-9]{1}[a-z0-9-]{0,30}[a-z0-9]{1}$"

	// ArtifactRefRegex is a regex pattern for validating an OCI artifact reference.
	ArtifactRefRegex = "^[a-z0-9_.\\-\\/]+(:.*)?(@sha256:.*)?$"

	// UUIDRegex is a regex pattern for validating a UUID.
	UUIDRegex = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

	noProxyExceptions  = []string{"*", "localhost", "kubernetes"}
	domainRegex        = regexp.MustCompile("^" + domain + "$")
	tldRegex           = regexp.MustCompile("^" + topLevelDomain + "$")
	noProxyDomainRegex = regexp.MustCompile("^" + "\\." + domain + "$")
	domainPortRegex    = regexp.MustCompile("^" + domain + port + "$")
	ipPortRegex        = regexp.MustCompile("^" + ip + port + "$")
)

// TUI is a text-user-interface for eliciting user input.
type TUI interface {
	GetBool(prompt string, defaultVal bool) (bool, error)
	GetText(prompt, defaultVal, mask string, optional bool, validate func(string) error) (string, error)
	GetTextSlice(prompt, defaultVal string, optional bool, validate func([]string) error) ([]string, error)
	GetSelection(prompt string, options []string) (string, error)
	GetMultiSelection(prompt string, options []string, minSelections int) ([]string, error)
}

// PtermTUI is a text-user-interface implementation using the pterm library.
type PtermTUI struct{}

// GetBool prompts a bool from the user while automatically appending a ? character to the end of the prompt message.
func (p PtermTUI) GetBool(prompt string, defaultVal bool) (bool, error) {
	return pterm.DefaultInteractiveConfirm.
		WithDefaultText(prompt + "?").
		WithDefaultValue(defaultVal).
		WithOnInterruptFunc(exit).
		Show()
}

// GetText prompts a string from the user with optional validation.
// If the default value is >60 characters, multiline input with tab completion is used.
// Otherwise, single line input with enter completion is used.
func (p PtermTUI) GetText(prompt, defaultVal, mask string, optional bool, validate func(string) error) (string, error) {
	for {
		if optional {
			prompt = fmt.Sprintf("%s (optional, hit enter to skip)", prompt)
		}

		// Workaround for https://github.com/pterm/pterm/issues/560:
		// Inputs longer than the terminal width are handled better with
		// multiline enabled, but the prompt is still repeated after every key press.
		var multiline bool
		if len(defaultVal) > 60 {
			multiline = true
		}

		s, err := pterm.DefaultInteractiveTextInput.
			WithDefaultValue(defaultVal).
			WithMask(mask).
			WithMultiLine(multiline).
			WithOnInterruptFunc(exit).
			Show(prompt)
		if err != nil {
			return "", err
		}

		if err := validate(s); err != nil {
			logger.Info("Validation failed", logger.Args("input", s, "error", err.Error()))
			continue
		}
		return s, nil
	}
}

// GetTextSlice prompts a slice of strings from the user with optional validation.
func (p PtermTUI) GetTextSlice(prompt, defaultVal string, optional bool, validate func([]string) error) ([]string, error) {
	for {
		if optional {
			prompt = fmt.Sprintf("%s (optional, newline separated values, hit tab to skip)", prompt)
		} else {
			prompt = fmt.Sprintf("%s (newline separated values)", prompt)
		}

		s, err := pterm.DefaultInteractiveTextInput.
			WithDefaultValue(defaultVal).
			WithMultiLine(true).
			WithOnInterruptFunc(exit).
			Show(prompt)
		if err != nil {
			return nil, err
		}

		lines := make([]string, 0)
		for _, line := range strings.Split(s, "\n") {
			line := strings.TrimSpace(line)
			if line != "" {
				lines = append(lines, line)
			}
		}
		if err := validate(lines); err != nil {
			logger.Info("Validation failed", logger.Args("input", s, "error", err.Error()))
			continue
		}

		return lines, nil
	}
}

// GetSelection prompts the user to select an option from a list of options.
func (p PtermTUI) GetSelection(prompt string, options []string) (string, error) {
	return pterm.DefaultInteractiveSelect.
		WithDefaultText(prompt).
		WithOptions(options).
		WithOnInterruptFunc(exit).
		Show()
}

// GetMultiSelection prompts the user to select multiple options from a list of options.
func (p PtermTUI) GetMultiSelection(prompt string, options []string, minSelections int) ([]string, error) {
	for {
		selections, err := pterm.DefaultInteractiveMultiselect.
			WithDefaultText(prompt).
			WithOptions(options).
			Show()
		if err != nil {
			return nil, err
		}
		if len(selections) < minSelections {
			logger.Info("Minimum selection required", logger.Args(minSelections))
			continue
		}
		return selections, nil
	}
}

// ---------
// Selection
// ---------

// ChoiceItem is a struct representing a selectable item.
type ChoiceItem struct {
	ID   string
	Name string
}

func exit() {
	logger.Fatal("Exiting CLI...")
}

// Select prompts the user to select a single option from a list of options.
func Select(prompt string, options []string) (string, error) {
	if len(options) == 0 {
		return "", fmt.Errorf("failure in Select: no options available: %s", prompt)
	}
	choice, err := Tui.GetSelection(prompt, options)
	if err != nil {
		return "", errors.Wrap(err, "failure in Select")
	}
	return choice, nil
}

// SelectID prompts the user to select an item from a list of ChoiceItems.
// Useful for presenting a pretty name to the user, but obtaining an ID
// associated with the pretty name.
func SelectID(prompt string, items []ChoiceItem) (*ChoiceItem, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("failure in SelectID: no options available: %s", prompt)
	}

	options := make([]string, 0)
	optionsMap := make(map[string]*ChoiceItem, 0)

	for _, i := range items {
		i := i
		options = append(options, i.Name)
		optionsMap[i.Name] = &i
	}

	choice, err := Tui.GetSelection(prompt, options)
	if err != nil {
		return nil, errors.Wrap(err, "failure in SelectID")
	}

	return optionsMap[choice], nil
}

// MultiSelect prompts the user to select at least n options from a list of options.
func MultiSelect(prompt string, options []string, minSelections int) ([]string, error) {
	if len(options) == 0 {
		return nil, fmt.Errorf("failure in MultiSelect: no options available: %s", prompt)
	}
	selections, err := Tui.GetMultiSelection(prompt, options, minSelections)
	if err != nil {
		return nil, errors.Wrap(err, "failure in MultiSelect")
	}
	return selections, nil
}

// -----
// Input
// -----

// ReadBool prompts the user to enter a boolean value.
func ReadBool(prompt string, defaultVal bool) (bool, error) {
	b, err := Tui.GetBool(prompt, defaultVal)
	if err != nil {
		return b, errors.Wrap(err, "failure in ReadBool")
	}
	return b, nil
}

// ReadInt prompts the user to enter an integer value with optional min and max values.
func ReadInt(prompt, defaultVal string, minVal, maxVal int) (int, error) {
	validate := func(input string) error {
		i, err := strconv.Atoi(input)
		if err != nil {
			return err
		}
		if minVal > 0 && i < minVal {
			return fmt.Errorf("minimum is %d", minVal)
		} else if maxVal > 0 && i > maxVal {
			return fmt.Errorf("maximum is %d", maxVal)
		}
		return nil
	}

	s, err := Tui.GetText(prompt, defaultVal, "", false, validate)
	if err != nil {
		return -1, errors.Wrap(err, "failure in ReadInt")
	}
	return strconv.Atoi(s)
}

// ReadText prompts the user to enter a string value, optionally with a maximum length.
func ReadText(label, defaultVal string, optional bool, maxLen int) (string, error) {
	s, err := Tui.GetText(label, defaultVal, "", optional, validateStringFunc(optional, maxLen))
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadText")
	}
	return strings.TrimSpace(s), nil
}

// ReadTextSlice prompts the user to enter a slice of strings with optional regex validation.
func ReadTextSlice(label, defaultVal, errMsg, regexPattern string, optional bool) ([]string, error) {
	validate := func(input []string) error {
		if !optional {
			if len(input) == 0 {
				return ErrInputMandatory
			}
			if len(slices.Compact(input)) == 1 && slices.Compact(input)[0] == "" {
				return ErrInputMandatory
			}
		}
		if regexPattern == "" {
			return nil
		}
		for _, line := range input {
			if err := validateRegex(line, errMsg, regexPattern); err != nil {
				return err
			}
		}
		return nil
	}

	s, err := Tui.GetTextSlice(label, defaultVal, optional, validate)
	if err != nil {
		return nil, errors.Wrap(err, "failure in ReadTextSlice")
	}
	return s, nil
}

// ReadTextSliceCustom prompts the user to enter a slice of strings with custom validation.
func ReadTextSliceCustom(label, defaultVal string, optional bool, validate func(input []string) error) ([]string, error) {
	s, err := Tui.GetTextSlice(label, defaultVal, optional, validate)
	if err != nil {
		return nil, errors.Wrap(err, "failure in ReadTextSliceCustom")
	}
	return s, nil
}

// ReadIntSlice prompts the user to enter a slice of integers.
func ReadIntSlice(label, defaultVal string, optional bool) ([]int, error) {
	validate := func(input []string) error {
		if !optional {
			if len(input) == 0 {
				return ErrInputMandatory
			}
			if len(slices.Compact(input)) == 1 && slices.Compact(input)[0] == "" {
				return ErrInputMandatory
			}
		}
		for _, line := range input {
			if _, err := strconv.Atoi(line); err != nil {
				return fmt.Errorf("input %s is not an integer", line)
			}
		}
		return nil
	}

	s, err := Tui.GetTextSlice(label, defaultVal, optional, validate)
	if err != nil {
		return nil, errors.Wrap(err, "failure in ReadIntSlice")
	}

	ints := make([]int, 0)
	for _, line := range s {
		i, _ := strconv.Atoi(line)
		ints = append(ints, i)
	}

	return ints, nil
}

// ReadURLSlice prompts the user to enter a slice of URLs.
func ReadURLSlice(label, defaultVal, errMsg string, optional bool) ([]string, error) {
	validate := func(input []string) error {
		if !optional {
			if len(input) == 0 {
				return ErrInputMandatory
			}
			if len(slices.Compact(input)) == 1 && slices.Compact(input)[0] == "" {
				return ErrInputMandatory
			}
		}
		for _, line := range input {
			if err := validateURL(line, errMsg); err != nil {
				return err
			}
		}
		return nil
	}

	s, err := Tui.GetTextSlice(label, defaultVal, optional, validate)
	if err != nil {
		return nil, errors.Wrap(err, "failure in ReadURLSlice")
	}
	return s, nil
}

// ReadTextRegex prompts the user to enter a string value with regex validation.
func ReadTextRegex(label, defaultVal, errMsg, regexPattern string) (string, error) {
	validate := func(input string) error {
		if input == "" {
			return ErrInputMandatory
		}
		if err := validateRegex(input, errMsg, regexPattern); err != nil {
			return err
		}
		return nil
	}

	s, err := Tui.GetText(label, defaultVal, "", false, validate)
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadTextRegex")
	}
	return s, nil
}

// ReadSemVer prompts the user to enter a semantic version.
func ReadSemVer(label, defaultVal, errMsg string) (string, error) {
	validate := func(input string) error {
		if input == "" {
			return ErrInputMandatory
		}
		if !strings.HasPrefix(input, "v") {
			return fmt.Errorf("input %s must start with a 'v'; %s", input, errMsg)
		}
		if err := validateRegex(input, errMsg, semver.SemVerRegex); err != nil {
			return err
		}
		return nil
	}

	s, err := Tui.GetText(label, defaultVal, "", false, validate)
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadSemVer")
	}
	return s, nil
}

// ReadPassword prompts the user to enter a password with an optional maximum length.
// User input is masked with the '*' character.
func ReadPassword(label, defaultVal string, optional bool, maxLen int) (string, error) {
	s, err := Tui.GetText(label, defaultVal, "*", optional, validateStringFunc(optional, maxLen))
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadPassword")
	}
	return s, nil
}

// ReadBasicCreds prompts the user to enter a username and password.
// User input for the password is always masked and the username can optionally be masked.
func ReadBasicCreds(usernamePrompt, passwordPrompt, defaultUsername, defaultPassword string, optional, maskUser bool) (string, string, error) {
	var username string
	var err error

	if maskUser {
		username, err = ReadPassword(usernamePrompt, defaultUsername, optional, -1)
		if err != nil {
			return "", "", err
		}
	} else {
		username, err = ReadText(usernamePrompt, defaultUsername, optional, -1)
		if err != nil {
			return "", "", err
		}
	}
	password, err := ReadPassword(passwordPrompt, defaultPassword, optional, -1)
	if err != nil {
		return "", "", err
	}

	return username, password, nil
}

// ReadURL prompts the user to enter a URL.
func ReadURL(label, defaultVal, errMsg string, optional bool) (string, error) {
	validate := func(input string) error {
		if input == "" {
			if !optional {
				return ErrInputMandatory
			}
			return nil
		}
		return validateURL(input, errMsg)
	}

	s, err := Tui.GetText(label, defaultVal, "", optional, validate)
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadURL")
	}

	s = strings.TrimRight(s, "/")
	return s, nil
}

// ReadURLRegex prompts the user to enter a URL with additional regex validation.
func ReadURLRegex(label, defaultVal, errMsg, regexPattern string) (string, error) {
	validate := func(input string) error {
		if err := validateRegex(input, errMsg, regexPattern); err != nil {
			return err
		}
		return validateURL(input, errMsg)
	}

	s, err := Tui.GetText(label, defaultVal, "", false, validate)
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadURLRegex")
	}

	s = strings.TrimRight(s, "/")
	return s, nil
}

// ReadDomains prompts the user to enter a comma-separated string of FQDNs,
// optionally with a maximum number of values.
func ReadDomains(label, defaultVal, errMsg string, optional bool, maxVals int) (string, error) {
	validate := func(input string) error {
		if input == "" {
			if !optional {
				return ErrInputMandatory
			}
			return nil
		}
		vals := strings.Split(input, ",")
		if maxVals > 0 && len(vals) > maxVals {
			return fmt.Errorf("%s: maximum domains: %d", errMsg, maxVals)
		}
		for _, v := range vals {
			if !(domainRegex.Match([]byte(v)) && validateDomain(v)) {
				return errors.New(errMsg)
			}
		}
		return nil
	}

	s, err := Tui.GetText(label, defaultVal, "", optional, validate)
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadDomains")
	}
	return s, nil
}

// ReadIPs prompts the user to enter a comma-separated string of IPv4 or IPv6 addresses,
// optionally with a maximum number of values.
func ReadIPs(label, defaultVal, errMsg string, optional bool, maxVals int) (string, error) {
	validate := func(input string) error {
		if input == "" {
			if !optional {
				return ErrInputMandatory
			}
			return nil
		}
		vals := strings.Split(input, ",")
		if maxVals > 0 && len(vals) > maxVals {
			return fmt.Errorf("%s: maximum IPs: %d", errMsg, maxVals)
		}
		for _, v := range vals {
			if ip := net.ParseIP(v); ip == nil {
				return errors.New(errMsg)
			}
		}
		return nil
	}

	s, err := Tui.GetText(label, defaultVal, "", optional, validate)
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadIP")
	}
	return s, nil
}

// ReadDomainsOrIPs prompts the user to enter a comma-separated string of FQDNs or IPv4/IPv6
// addresses, optionally with a maximum number of values.
func ReadDomainsOrIPs(label, defaultVal, errMsg string, optional bool, maxVals int) (string, error) {
	validate := func(input string) error {
		if input == "" {
			if !optional {
				return ErrInputMandatory
			}
			return nil
		}
		vals := strings.Split(input, ",")
		if maxVals > 0 && len(vals) > maxVals {
			return fmt.Errorf("%s: maximum domains or IPs: %d", errMsg, maxVals)
		}
		for _, v := range vals {
			ip := net.ParseIP(v)
			isIPWithPort := ipPortRegex.Match([]byte(v))
			isDomain := domainRegex.Match([]byte(v)) && validateDomain(v)
			if ip != nil || isIPWithPort || isDomain {
				continue
			}
			return fmt.Errorf("%s: %s is neither an IP, IP:port, or an FQDN", errMsg, v)
		}
		return nil
	}

	s, err := Tui.GetText(label, defaultVal, "", optional, validate)
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadDomainsOrIPs")
	}
	return s, nil
}

// ReadDomainOrIPNoPort prompts the user to enter an FQDN or an IPv4/IPv6 address without a port.
func ReadDomainOrIPNoPort(label, defaultVal, errMsg string, optional bool) (string, error) {
	validate := func(input string) error {
		if input == "" {
			if !optional {
				return ErrInputMandatory
			}
			return nil
		}

		ip := net.ParseIP(input)
		isDomain := domainRegex.Match([]byte(input)) && validateDomain(input)
		if ip != nil || isDomain {
			return nil
		}
		return fmt.Errorf("%s: %s is neither an IP or an FQDN", errMsg, input)
	}

	s, err := Tui.GetText(label, defaultVal, "", optional, validate)
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadDomainOrIPNoPort")
	}
	return s, nil
}

// ReadDomainsOrIPsOrURLs prompts the user to enter a comma-separated string of FQDNs or IPv4/IPv6
// addresses or URLs, optionally with a maximum number of values.
func ReadDomainsOrIPsOrURLs(label, defaultVal, errMsg string, optional bool, maxVals int) (string, error) {
	validate := func(input string) error {
		if input == "" {
			if !optional {
				return ErrInputMandatory
			}
			return nil
		}
		vals := strings.Split(input, ",")
		if maxVals > 0 && len(vals) > maxVals {
			return fmt.Errorf("%s: maximum domains or IPs or URLs: %d", errMsg, maxVals)
		}
		for _, v := range vals {
			ip := net.ParseIP(v)
			isIPWithPort := ipPortRegex.Match([]byte(v))
			isDomain := domainRegex.Match([]byte(v)) && validateDomain(v)
			isURL := validateURL(input, errMsg) == nil
			if ip != nil || isIPWithPort || isDomain || isURL {
				continue
			}
			return fmt.Errorf("%s: %s is neither an IP, IP:port, an FQDN, nor a URL", errMsg, v)
		}
		return nil
	}

	s, err := Tui.GetText(label, defaultVal, "", optional, validate)
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadDomainsOrIPsOrURLs")
	}
	return s, nil
}

// ReadCIDRs prompts the user to enter a comma-separated string of CIDR blocks,
// optionally with a maximum number of values.
func ReadCIDRs(label, defaultVal, errMsg string, optional bool, maxVals int) (string, error) {
	validate := func(input string) error {
		if input == "" {
			if !optional {
				return ErrInputMandatory
			}
			return nil
		}
		vals := strings.Split(input, ",")
		if maxVals > 0 && len(vals) > maxVals {
			return fmt.Errorf("%s: maximum CIDRs: %d", errMsg, maxVals)
		}
		for _, v := range vals {
			if _, _, err := net.ParseCIDR(v); err != nil {
				return errors.Wrap(err, errMsg)
			}
		}
		return nil
	}

	s, err := Tui.GetText(label, defaultVal, "", optional, validate)
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadCIDRs")
	}
	return s, nil
}

// ReadFilePath prompts the user to enter a fully qualified path for a file on the
// local file system.
func ReadFilePath(label, defaultVal, errMsg string, optional bool) (string, error) {
	validate := func(input string) error {
		if input == "" {
			if !optional {
				return ErrInputMandatory
			}
			return nil
		}
		fileInfo, err := os.Stat(input)
		if err != nil {
			return errors.Wrap(err, errMsg)
		}
		if fileInfo.IsDir() {
			return fmt.Errorf("%s: input %s is a directory, not a file", errMsg, input)
		}
		return nil
	}

	s, err := Tui.GetText(label, defaultVal, "", optional, validate)
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadFilePath")
	}
	return s, nil
}

// ReadK8sName prompts the user to enter a string which is a valid Kubernetes name.
// Inputs must be both a Kubernetes "qualified name" and compliant with DNS (RFC 1123).
func ReadK8sName(label, defaultVal string, optional bool) (string, error) {
	validate := func(input string) error {
		if err := validateStringFunc(optional, -1)(input); err != nil {
			return err
		}
		return validateK8sName(input, optional)
	}

	s, err := Tui.GetText(label, defaultVal, "", optional, validate)
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadK8sName")
	}
	return s, nil
}

// ReadCACert loads and validates a CA certificate from the local file system when caCertPathOverride is provided.
// Otherwise, the user is prompted to enter a CA certificate path and the certificate at that path is loaded and
// validated.
func ReadCACert(prompt string, defaultCaCertPath, caCertPathOverride string) (caCertPath string, caCertName string, caCertData []byte, err error) {
	if caCertPathOverride != "" {
		caCertPath = caCertPathOverride
	} else {
		logger.Info("Optionally enter the file path to your desired CA certificate, e.g., /usr/local/share/ca-certificates/ca.crt")
		logger.Info("Press enter to skip if your certificates are publicly verifiable")
		caCertPath, err = ReadFilePath(prompt, defaultCaCertPath, "Invalid filepath specified", true)
	}
	if err != nil {
		return "", "", nil, err
	}
	if caCertPath == "" {
		return "", "", nil, nil
	}
	caFile, _ := os.Stat(caCertPath)
	caBytes, err := os.ReadFile(caCertPath) //#nosec
	if err != nil {
		return "", "", nil, err
	}
	// Validate CA cert
	var blocks []byte
	rest := caBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return "", "", nil, fmt.Errorf("PEM parse failure for %s", caCertPath)
		}
		blocks = append(blocks, block.Bytes...)
		if len(rest) == 0 {
			break
		}
	}
	if _, err = x509.ParseCertificates(blocks); err != nil {
		return "", "", nil, err
	}
	return caCertPath, caFile.Name(), caBytes, nil
}

func validateRegex(input, errMsg, regexPattern string) error {
	r, err := regexp.Compile(regexPattern)
	if err != nil {
		return errors.Wrap(err, errMsg)
	}
	m := r.Find([]byte(input))
	if string(m) == input {
		return nil
	}
	return fmt.Errorf("input %s does not match regex %s; %s", input, regexPattern, errMsg)
}

func validateURL(input, errMsg string) error {
	if _, err := url.ParseRequestURI(input); err != nil {
		return errors.Wrap(err, errMsg)
	}
	if u, err := url.Parse(input); err != nil {
		return errors.Wrap(err, errMsg)
	} else if u.Scheme == "" || u.Host == "" {
		return errors.New(errMsg)
	}
	return nil
}

// ValidateNoProxy validates input for the NO_PROXY environment variable.
// See: https://pkg.go.dev/golang.org/x/net/http/httpproxy#Config
func ValidateNoProxy(s string) error {
	if s == "" {
		return nil
	}

	vBytes := []byte(s)
	ip := net.ParseIP(s)
	isIPWithPort := ipPortRegex.Match(vBytes)
	isDomain := domainRegex.Match(vBytes) && validateDomain(s)
	isDomainWithPort := domainPortRegex.Match(vBytes)
	isNoProxyDomain := noProxyDomainRegex.Match(vBytes) && validateDomain(s)
	isTopLevelDomain := tldRegex.Match(vBytes)
	_, _, cidrErr := net.ParseCIDR(s)
	isException := slices.Contains(noProxyExceptions, s)

	if ip != nil || isIPWithPort || cidrErr == nil || isDomain || isDomainWithPort || isNoProxyDomain || isTopLevelDomain || isException {
		return nil
	}

	logger.Error("invalid no_proxy input", logger.Args(s, "is neither an IP, CIDR, domain, '*', domain:port, or IP:port"))
	return ErrValidationFailed
}

// ValidateSSHPublicKey validates that the input string is an SSH public key.
func ValidateSSHPublicKey(s string) error {
	if s == "" {
		return nil
	}
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		logger.Error("invalid SSH public key", logger.Args("input", s, "error", err))
		return ErrValidationFailed
	}
	return nil
}

// ValidateJSON validates that the input string is valid JSON.
func ValidateJSON(s string) error {
	if s == "" {
		return nil
	}
	if !json.Valid([]byte(s)) {
		logger.Error("invalid JSON input", logger.Args("input", s))
		return ErrValidationFailed
	}
	return nil
}

// validateDomain ensures that no occurrence of consecutive dashes are found.
// This is necessary in addition to the domain regex, since go doesn't support negative lookaheads.
func validateDomain(domain string) bool {
	return !strings.Contains(domain, "--")
}

func validateStringFunc(optional bool, maxLen int) func(input string) error {
	return func(input string) error {
		if !optional && input == "" {
			return ErrInputMandatory
		}
		fieldLen := len(input)
		if maxLen > 0 && fieldLen > maxLen {
			return fmt.Errorf("maximum length of %d chars exceeded. input length: %d", maxLen, fieldLen)
		}
		return nil
	}
}

func validateK8sName(name string, optional bool) error {
	if optional && name == "" {
		return nil
	}
	if errs := validation.IsQualifiedName(name); errs != nil {
		return errors.New(strings.Join(errs, ", "))
	}
	if errs := validation.IsDNS1123Subdomain(name); errs != nil {
		return errors.New(strings.Join(errs, ", "))
	}
	return nil
}
