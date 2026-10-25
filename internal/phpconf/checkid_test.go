package phpconf

import "testing"

func TestRiskCheckID(t *testing.T) {
	cases := []struct {
		r    Risk
		want string
	}{
		{Risk{Runtime: "php8.2-fpm", Pool: "www", Directive: "allow_url_include"}, "PHP_ALLOW_URL_INCLUDE@php8.2-fpm/www"},
		{Risk{Runtime: "ea-php82", Directive: "display_errors"}, "PHP_DISPLAY_ERRORS@ea-php82"},
		{Risk{Runtime: "site:alice.example", Directive: "display_errors"}, "PHP_DISPLAY_ERRORS@site:alice.example"},
		{Risk{Runtime: "ea-php82", Directive: "expose_php"}, ""},
	}
	for _, c := range cases {
		if got := c.r.CheckID(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.r, got, c.want)
		}
		if c.want != "" {
			if _, _, _, _, ok := ParseID(c.want); !ok {
				t.Errorf("%q does not parse as a check ID", c.want)
			}
		}
	}
}
