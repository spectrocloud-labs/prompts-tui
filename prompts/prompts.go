package prompts

import (
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
	logger = pterm.DefaultLogger

	// Exported to enable monkey-patching
	Tui TUI = PtermTUI{}

	ValidationError     = errors.New("validation failed")
	InputMandatoryError = errors.New("input is mandatory")

	// Exported regex patterns for use with ReadTextRegex
	KindClusterRegex = "^[a-z0-9]{1}[a-z0-9-]{0,30}[a-z0-9]{1}$"
	ArtifactRefRegex = "^[a-z0-9_.\\-\\/]+(:.*)?(@sha256:.*)?$"
	UUIDRegex        = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

	noProxyExceptions  = []string{"*", "localhost", "kubernetes"}
	domainRegex        = regexp.MustCompile("^" + domain + "$")
	tldRegex           = regexp.MustCompile("^" + topLevelDomain + "$")
	noProxyDomainRegex = regexp.MustCompile("^" + "\\." + domain + "$")
	domainPortRegex    = regexp.MustCompile("^" + domain + port + "$")
	ipPortRegex        = regexp.MustCompile("^" + ip + port + "$")
)

type TUI interface {
	GetBool(prompt string, defaultVal bool) (bool, error)
	GetText(prompt, defaultVal, mask string, optional bool, validate func(string) error) (string, error)
	GetSelection(prompt string, options []string) (string, error)
	GetMultiSelection(prompt string, options []string, minSelections int) ([]string, error)
}

type PtermTUI struct{}

// GetBool prompts a bool from the user while automatically appending a ? character to the end of the prompt message.
func (p PtermTUI) GetBool(prompt string, defaultVal bool) (bool, error) {
	return pterm.DefaultInteractiveConfirm.
		WithDefaultText(prompt + "?").
		WithDefaultValue(defaultVal).
		WithOnInterruptFunc(exit).
		Show()
}

func (p PtermTUI) GetText(prompt, defaultVal, mask string, optional bool, validate func(string) error) (string, error) {
	for {
		if optional {
			prompt = fmt.Sprintf("%s (optional, hit enter to skip)", prompt)
		}

		// workaround for https://github.com/pterm/pterm/issues/560:
		// inputs longer than the terminal width are handled better with
		// multiline enabled, but the prompt is still repeated after every key press
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

func (p PtermTUI) GetSelection(prompt string, options []string) (string, error) {
	return pterm.DefaultInteractiveSelect.
		WithDefaultText(prompt).
		WithOptions(options).
		WithOnInterruptFunc(exit).
		Show()
}

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

type ChoiceItem struct {
	ID   string
	Name string
}

func exit() {
	logger.Fatal("Exiting CLI...")
}

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

func ReadBool(prompt string, defaultVal bool) (bool, error) {
	b, err := Tui.GetBool(prompt, defaultVal)
	if err != nil {
		return b, errors.Wrap(err, "failure in ReadBool")
	}
	return b, nil
}

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

func ReadText(label, defaultVal string, optional bool, maxLen int) (string, error) {
	s, err := Tui.GetText(label, defaultVal, "", optional, validateStringFunc(optional, maxLen))
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadText")
	}
	return strings.TrimSpace(s), nil
}

func ReadTextRegex(label, defaultVal, errMsg, regexPattern string) (string, error) {
	validate := func(input string) error {
		if input == "" {
			return InputMandatoryError
		}
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

	s, err := Tui.GetText(label, defaultVal, "", false, validate)
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadTextRegex")
	}
	return s, nil
}

func ReadSemVer(label, defaultVal, errMsg string) (string, error) {
	validate := func(input string) error {
		if input == "" {
			return InputMandatoryError
		}
		if !strings.HasPrefix(input, "v") {
			return fmt.Errorf("input %s must start with a 'v'; %s", input, errMsg)
		}
		r, err := regexp.Compile(semver.SemVerRegex)
		if err != nil {
			return errors.Wrap(err, errMsg)
		}
		m := r.Find([]byte(input))
		if string(m) == input {
			return nil
		}
		return fmt.Errorf("input %s does not match regex %s; %s", input, semver.SemVerRegex, errMsg)
	}

	s, err := Tui.GetText(label, defaultVal, "", false, validate)
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadSemVer")
	}
	return s, nil
}

func ReadPassword(label, defaultVal string, optional bool, maxLen int) (string, error) {
	s, err := Tui.GetText(label, defaultVal, "*", optional, validateStringFunc(optional, maxLen))
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadPassword")
	}
	return s, nil
}

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

func ReadURL(label, defaultVal, errMsg string, optional bool) (string, error) {
	validate := func(input string) error {
		if input == "" {
			if !optional {
				return InputMandatoryError
			} else {
				return nil
			}
		}

		_, err := url.ParseRequestURI(input)
		if err != nil {
			return errors.Wrap(err, errMsg)
		}

		u, err := url.Parse(input)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return errors.Wrap(err, errMsg)
		}
		return nil
	}

	s, err := Tui.GetText(label, defaultVal, "", optional, validate)
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadURL")
	}

	s = strings.TrimRight(s, "/")
	return s, nil
}

func ReadURLRegex(label, defaultVal, errMsg, regexPattern string) (string, error) {
	validate := func(input string) error {
		r, err := regexp.Compile(regexPattern)
		if err != nil {
			return errors.Wrap(err, errMsg)
		}
		m := r.Find([]byte(input))
		if string(m) != input {
			return fmt.Errorf("input %s does not match regex %s; %s", input, regexPattern, errMsg)
		}

		_, err = url.ParseRequestURI(input)
		if err != nil {
			return errors.Wrap(err, errMsg)
		}

		u, err := url.Parse(input)
		if err != nil {
			return errors.Wrap(err, errMsg)
		} else if u.Scheme == "" || u.Host == "" {
			return errors.New(errMsg)
		}
		return nil
	}

	s, err := Tui.GetText(label, defaultVal, "", false, validate)
	if err != nil {
		return s, errors.Wrap(err, "failure in ReadURLRegex")
	}

	s = strings.TrimRight(s, "/")
	return s, nil
}

func ReadDomains(label, defaultVal, errMsg string, optional bool, maxVals int) (string, error) {
	validate := func(input string) error {
		if input == "" {
			if !optional {
				return InputMandatoryError
			} else {
				return nil
			}
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

func ReadIPs(label, defaultVal, errMsg string, optional bool, maxVals int) (string, error) {
	validate := func(input string) error {
		if input == "" {
			if !optional {
				return InputMandatoryError
			} else {
				return nil
			}
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

func ReadDomainsOrIPs(label, defaultVal, errMsg string, optional bool, maxVals int) (string, error) {
	validate := func(input string) error {
		if input == "" {
			if !optional {
				return InputMandatoryError
			} else {
				return nil
			}
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

func ReadDomainOrIPNoPort(label, defaultVal, errMsg string, optional bool) (string, error) {
	validate := func(input string) error {
		if input == "" {
			if !optional {
				return InputMandatoryError
			} else {
				return nil
			}
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

func ReadCIDRs(label, defaultVal, errMsg string, optional bool, maxVals int) (string, error) {
	validate := func(input string) error {
		if input == "" {
			if !optional {
				return InputMandatoryError
			} else {
				return nil
			}
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

func ReadFilePath(label, defaultVal, errMsg string, optional bool) (string, error) {
	validate := func(input string) error {
		if input == "" {
			if !optional {
				return InputMandatoryError
			} else {
				return nil
			}
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
	return ValidationError
}

func ValidateSSHPublicKey(s string) error {
	if s == "" {
		return nil
	}
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		logger.Error("invalid SSH public key", logger.Args("input", s, "error", err))
		return ValidationError
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
			return InputMandatoryError
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
