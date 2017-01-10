package main

import "strings"

type AirlinkRule struct {
	classic *ClassicRule
	body string
	name string

	direct []string
	proxy []string
	reject []string

	include []string
}

func (rule *AirlinkRule) convert() {
	// General Bypass
	rule.direct = append(rule.direct, rule.classic.general.bypass...)

	// General Direct
	rule.direct = append(rule.direct, rule.classic.general.direct...)

	// Rule Direct
	for _, blocks := range rule.classic.rules {
		switch blocks.typo {
		case TYPO_DOMAIN:
			switch strings.ToLower(blocks.action) {
			case "direct": rule.direct = append(rule.direct, blocks.value)
			case "proxy": rule.proxy = append(rule.proxy, blocks.value)
			case "reject": rule.reject = append(rule.reject, blocks.value)
			}
		case TYPO_DOMAIN_SUFFIX:
			switch strings.ToLower(blocks.action) {
			case "direct": rule.direct = append(rule.direct, "*." + blocks.value)
			case "proxy": rule.proxy = append(rule.proxy, "*." + blocks.value)
			case "reject": rule.reject = append(rule.reject, "*." + blocks.value)
			}
		case TYPO_IP_CIDR:
			switch strings.ToLower(blocks.action) {
			case "direct": rule.direct = append(rule.direct, blocks.value)
			case "proxy": rule.proxy = append(rule.proxy, blocks.value)
			case "reject": rule.reject = append(rule.reject, blocks.value)
			}
		}
	}
}

func (rule *AirlinkRule) build() {
	rule.body = ""
	rule.body += "@" + rule.name + "\n\n"
	rule.body += "[Proxy]" + "\n"
	rule.body += strings.Join(rule.proxy, "\n") + "\n\n"
	rule.body += "[Direct]" + "\n"
	rule.body += strings.Join(rule.direct, "\n") + "\n\n"
	rule.body += "[Reject]" + "\n"
	rule.body += strings.Join(rule.reject, "\n") + "\n"
}

func newAirlinkRuleByClassic(name string, classic *ClassicRule) *AirlinkRule {
	rule := new(AirlinkRule)
	if len(name) == 0 {
		name = "Unnamed"
	}
	rule.name = name
	rule.classic = classic
	rule.convert()
	rule.build()
	return rule
}