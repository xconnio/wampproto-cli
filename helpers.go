package wampprotocli

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
)

func HexToBase64(hexStr string) (string, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}

	base64Str := base64.StdEncoding.EncodeToString(bytes)
	return base64Str, nil
}

func DecodeHexOrBase64(str string) ([]byte, error) {
	bytes, err := hex.DecodeString(str)
	if err == nil {
		return bytes, nil
	}

	bytes, err = base64.StdEncoding.DecodeString(str)
	if err == nil {
		return bytes, nil
	}

	return nil, fmt.Errorf("must be in either hexadecimal or base64 format")
}

func FormatOutput(outputFormat, outputString string) (string, error) {
	switch outputFormat {
	case HexFormat:
		return outputString, nil

	case Base64Format:
		base64Str, err := HexToBase64(outputString)
		if err != nil {
			return "", err
		}

		return base64Str, err

	default:
		return "", fmt.Errorf("invalid output format")
	}
}

func FormatOutputBytes(outputFormat string, outputBytes []byte) (string, error) {
	switch outputFormat {
	case HexFormat:
		return hex.EncodeToString(outputBytes), nil

	case Base64Format:
		return base64.StdEncoding.EncodeToString(outputBytes), nil

	default:
		return "", fmt.Errorf("invalid output format")
	}
}

func StringsToTypedList(strings []string) (typedList []any) {
	for _, value := range strings {
		if number, errNumber := strconv.Atoi(value); errNumber == nil {
			typedList = append(typedList, number)
		} else if float, errFloat := strconv.ParseFloat(value, 64); errFloat == nil {
			typedList = append(typedList, float)
		} else if boolean, errBoolean := strconv.ParseBool(value); errBoolean == nil {
			typedList = append(typedList, boolean)
		} else {
			var jsonMap map[string]any
			var jsonMapList []map[string]any
			var list []any
			if errJson := json.Unmarshal([]byte(value), &jsonMap); errJson == nil {
				typedList = append(typedList, jsonMap)
			} else if errMapList := json.Unmarshal([]byte(value), &jsonMapList); errMapList == nil {
				typedList = append(typedList, jsonMapList)
			} else if errList := json.Unmarshal([]byte(value), &list); errList == nil {
				typedList = append(typedList, list)
			} else {
				typedList = append(typedList, value)
			}
		}
	}

	return typedList
}

func StringMapToTypedMap(stringMap map[string]string) (typesMap map[string]any) {
	typesMap = make(map[string]any)

	for key, value := range stringMap {
		if number, errNumber := strconv.Atoi(value); errNumber == nil {
			typesMap[key] = number
		} else if float, errFloat := strconv.ParseFloat(value, 64); errFloat == nil {
			typesMap[key] = float
		} else if boolean, errBoolean := strconv.ParseBool(value); errBoolean == nil {
			typesMap[key] = boolean
		} else {
			var jsonMap map[string]any
			var jsonMapList []map[string]any
			var list []any
			if errJson := json.Unmarshal([]byte(value), &jsonMap); errJson == nil {
				typesMap[key] = jsonMap
			} else if errMapList := json.Unmarshal([]byte(value), &jsonMapList); errMapList == nil {
				typesMap[key] = jsonMapList
			} else if errList := json.Unmarshal([]byte(value), &list); errList == nil {
				typesMap[key] = list
			} else {
				typesMap[key] = value
			}
		}
	}

	return typesMap
}
