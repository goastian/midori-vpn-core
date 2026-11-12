package auth

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

// RFC 7662 permits aud to be either one string or an array of strings.
type tokenAudience []string

func (audience *tokenAudience) UnmarshalJSON(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	switch value := value.(type) {
	case string:
		*audience = []string{value}
	case []any:
		multiple := make([]string, len(value))
		for index, item := range value {
			text, ok := item.(string)
			if !ok {
				return errors.New("token audience must contain only strings")
			}
			multiple[index] = text
		}
		*audience = multiple
	default:
		return errors.New("token audience must be a string or an array of strings")
	}
	return nil
}

func audienceMatches(audience []string, clientID string) bool {
	return strings.TrimSpace(clientID) != "" && slices.Contains(audience, clientID)
}
