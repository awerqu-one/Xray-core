package serial

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	stderrors "errors"
	"io"
	"strconv"

	"github.com/ghodss/yaml"
	"github.com/pelletier/go-toml"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	json_reader "github.com/xtls/xray-core/infra/conf/json"
)

type offset struct {
	line int
	char int
}

func findOffset(b []byte, o int) *offset {
	if o >= len(b) || o < 0 {
		return nil
	}

	line := 1
	char := 0
	for i, x := range b {
		if i == o {
			break
		}
		if x == '\n' {
			line++
			char = 0
		} else {
			char++
		}
	}

	return &offset{line: line, char: char}
}

// duplicateNameError is a repeated object name in config JSON.
// offset is a byte index into the comment-stripped document, or -1 if unknown.
type duplicateNameError struct {
	name   string
	offset int
}

func (e *duplicateNameError) Error() string {
	if e.name == "" {
		return "duplicate key"
	}
	return "duplicate key " + strconv.Quote(e.name)
}

// rejectDuplicateObjectKeys reports a repeated object name.
// encoding/json accepts duplicates: a scalar keeps the last value, and
// PortList.UnmarshalJSON appends, so a second "port" would listen as well.
// One key whose value is a list ("1-3", "80,443", or a JSON array) is not repeated.
// Syntax errors are left to the decoder that follows.
func rejectDuplicateObjectKeys(data []byte) error {
	dec := jsontext.NewDecoder(bytes.NewReader(data),
		jsontext.AllowDuplicateNames(false),
		jsontext.AllowInvalidUTF8(true),
	)
	_, err := dec.ReadValue()
	if err == nil || !stderrors.Is(err, jsontext.ErrDuplicateName) {
		return nil
	}
	dup := &duplicateNameError{offset: -1}
	var syn *jsontext.SyntacticError
	if stderrors.As(err, &syn) {
		dup.name = syn.JSONPointer.LastToken()
		dup.offset = int(syn.ByteOffset)
	}
	return dup
}

func readConfigError(data []byte, err error) error {
	var pos *offset
	switch tErr := errors.Cause(err).(type) {
	case *json.SyntaxError:
		pos = findOffset(data, int(tErr.Offset))
	case *json.UnmarshalTypeError:
		pos = findOffset(data, int(tErr.Offset))
	case *duplicateNameError:
		pos = findOffset(data, tErr.offset)
	}
	if pos != nil {
		return errors.New("failed to read config file at line ", pos.line, " char ", pos.char).Base(err)
	}
	return errors.New("failed to read config file").Base(err)
}

// DecodeJSONConfig reads from reader and decode the config into *conf.Config
// syntax error could be detected.
//
// Permissive: accepts JSON with Java/Python-style comments via json_reader.Reader.
// Used for local files and stdin where the config is human-edited.
func DecodeJSONConfig(reader io.Reader) (*conf.Config, error) {
	jsonConfig := &conf.Config{}

	jsonContent := bytes.NewBuffer(make([]byte, 0, 10240))
	if _, err := jsonContent.ReadFrom(&json_reader.Reader{Reader: reader}); err != nil {
		return nil, errors.New("failed to read config file").Base(err)
	}
	data := jsonContent.Bytes()
	if err := rejectDuplicateObjectKeys(data); err != nil {
		return nil, readConfigError(data, err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(jsonConfig); err != nil {
		return nil, readConfigError(data, err)
	}

	return jsonConfig, nil
}

// DecodeJSONConfigStrict reads standard RFC 8259 JSON without comment-stripping.
// Used for remote sources (http/https/http+unix) where the payload is produced by
// automated systems and cannot contain JSON5/JSONC extensions. Avoids the
// byte-by-byte comment stripper and TeeReader, which are significant overhead on
// large configs.
func DecodeJSONConfigStrict(reader io.Reader) (*conf.Config, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, errors.New("failed to read config file").Base(err)
	}
	if err := rejectDuplicateObjectKeys(data); err != nil {
		return nil, errors.New("failed to parse remote JSON config").Base(err)
	}
	jsonConfig := &conf.Config{}
	if err := json.Unmarshal(data, jsonConfig); err != nil {
		return nil, errors.New("failed to parse remote JSON config").Base(err)
	}
	return jsonConfig, nil
}

func LoadJSONConfig(reader io.Reader) (*core.Config, error) {
	jsonConfig, err := DecodeJSONConfig(reader)
	if err != nil {
		return nil, err
	}

	pbConfig, err := jsonConfig.Build()
	if err != nil {
		return nil, errors.New("failed to parse json config").Base(err)
	}

	return pbConfig, nil
}

// DecodeTOMLConfig reads from reader and decode the config into *conf.Config
// using github.com/pelletier/go-toml and map to convert toml to json.
func DecodeTOMLConfig(reader io.Reader) (*conf.Config, error) {
	tomlFile, err := io.ReadAll(reader)
	if err != nil {
		return nil, errors.New("failed to read config file").Base(err)
	}

	configMap := make(map[string]interface{})
	if err := toml.Unmarshal(tomlFile, &configMap); err != nil {
		return nil, errors.New("failed to convert toml to map").Base(err)
	}

	jsonFile, err := json.Marshal(&configMap)
	if err != nil {
		return nil, errors.New("failed to convert map to json").Base(err)
	}

	return DecodeJSONConfig(bytes.NewReader(jsonFile))
}

func LoadTOMLConfig(reader io.Reader) (*core.Config, error) {
	tomlConfig, err := DecodeTOMLConfig(reader)
	if err != nil {
		return nil, err
	}

	pbConfig, err := tomlConfig.Build()
	if err != nil {
		return nil, errors.New("failed to parse toml config").Base(err)
	}

	return pbConfig, nil
}

// DecodeYAMLConfig reads from reader and decode the config into *conf.Config
// using github.com/ghodss/yaml to convert yaml to json.
func DecodeYAMLConfig(reader io.Reader) (*conf.Config, error) {
	yamlFile, err := io.ReadAll(reader)
	if err != nil {
		return nil, errors.New("failed to read config file").Base(err)
	}

	jsonFile, err := yaml.YAMLToJSON(yamlFile)
	if err != nil {
		return nil, errors.New("failed to convert yaml to json").Base(err)
	}

	return DecodeJSONConfig(bytes.NewReader(jsonFile))
}

func LoadYAMLConfig(reader io.Reader) (*core.Config, error) {
	yamlConfig, err := DecodeYAMLConfig(reader)
	if err != nil {
		return nil, err
	}

	pbConfig, err := yamlConfig.Build()
	if err != nil {
		return nil, errors.New("failed to parse yaml config").Base(err)
	}

	return pbConfig, nil
}
