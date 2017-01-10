package main

import (
	"github.com/parnurzeal/gorequest"
	"strings"
	"regexp"
)

type GeneralSection struct {
	direct []string
	bypass []string
}

const (
	TYPO_DOMAIN = "DOMAIN"
	TYPO_DOMAIN_SUFFIX = "DOMAIN-SUFFIX"
	TYPO_DOMAIN_KEYWORD = "DOMAIN-KEYWORD"
	TYPO_IP_CIDR = "IP-CIDR"
	TYPO_GEOIP = "GEOIP"
)

type ClassicRule struct {
	raw string
	sections map[string]ConfSection

	general GeneralSection
	rules []RuleRow
}

type ConfSection struct {
	title string
	rows []string
}

type RuleRow struct {
	typo string
	value string
	action string
}

func (rule *ClassicRule) parseSections() {
	lines := strings.Split(rule.raw, "\n")
	currentSection := ConfSection{}

	rule.sections = map[string]ConfSection{}

	for _, line := range lines {
		shReg, _ := regexp.Compile(`\s*\[(.+)]`)
		if shReg.MatchString(line) {
			if len(currentSection.title) > 0 {
				rule.sections[currentSection.title] = currentSection
			}
			rs := shReg.FindStringSubmatch(line)
			currentSection = ConfSection{
				title: rs[1],
			}
		} else {
			cmlReg, _ := regexp.Compile(`\s*#`)
			eptReg, _ := regexp.Compile(`^\s*$`)
			if !cmlReg.MatchString(line) && !eptReg.MatchString(line) {
				cmpReg, _ := regexp.Compile(`#.*`)
				noCmLine := cmpReg.ReplaceAllString(line, "")
				currentSection.rows = append(currentSection.rows, noCmLine)
			}
		}
	}

	if len(currentSection.title) > 0 {
		rule.sections[currentSection.title] = currentSection
	}
}

func (rule *ClassicRule) parseRule() {
	// Parse General (Key-Value)
	generals := map[string]string{}
	for _, row := range rule.sections["General"].rows {
		keyEnd := strings.Index(row, "=")
		key := strings.TrimSpace(row[0:keyEnd])
		value := strings.TrimSpace(row[keyEnd+1:])
		generals[key] = value
	}
	for _, item := range strings.Split(generals["skip-proxy"], ",") {
		rule.general.direct = append(rule.general.direct, strings.TrimSpace(item))
	}
	for _, item := range strings.Split(generals["bypass-tun"], ",") {
		rule.general.bypass = append(rule.general.bypass, strings.TrimSpace(item))
	}

	// Parse Rules (Mark-Value-Mark)
	for _, row := range rule.sections["Rule"].rows {
		pieces := []string{}
		for _, block := range strings.Split(row, ",") {
			pieces = append(pieces, strings.TrimSpace(block))
		}
		if len(pieces) == 3 {
			rule.rules = append(rule.rules, RuleRow{
				typo: pieces[0],
				value: pieces[1],
				action: pieces[2],
			})
		}
	}
}

func newClassicRule(rawText string) *ClassicRule {
	rule := new(ClassicRule)
	rule.raw = rawText
	rule.parseSections()
	rule.parseRule()
	return rule
}

func newRemoteClassicRule(url string) *ClassicRule {
	request := gorequest.New()
	_, body, _ := request.Get(url).End()
	return newClassicRule(body)
}