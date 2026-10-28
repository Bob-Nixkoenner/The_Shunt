package i18n

import "strconv"

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case error:
		return x.Error()
	case interface{ String() string }:
		return x.String()
	default:
		return ""
	}
}
