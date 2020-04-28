// Copyright 2020 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// See the License for the specific language governing permissions and
// limitations under the License.

package filter

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Table represents a qualified table name.
type Table struct {
	// Schema is the name of the schema (database) containing this table.
	Schema string `toml:"db-name" json:"db-name" yaml:"db-name"`
	// Name is the unqualified table name.
	Name string `toml:"tbl-name" json:"tbl-name" yaml:"tbl-name"`
}

func (t *Table) lessThan(u *Table) bool {
	return t.Schema < u.Schema || t.Schema == u.Schema && t.Name < u.Name
}

// String implements the fmt.Stringer interface.
func (t *Table) String() string {
	if len(t.Name) > 0 {
		return fmt.Sprintf("`%s`.`%s`", t.Schema, t.Name)
	}
	return fmt.Sprintf("`%s`", t.Schema)
}

// MySQLReplicationRules is a set of rules based on MySQL's replication filter.
type MySQLReplicationRules struct {
	// DoTables is a whitelist of tables.
	DoTables []*Table `json:"do-tables" toml:"do-tables" yaml:"do-tables"`
	// DoDBs is the whitelist of schemas.
	DoDBs []string `json:"do-dbs" toml:"do-dbs" yaml:"do-dbs"`

	// IgnoreTables is a blacklist of tables.
	IgnoreTables []*Table `json:"ignore-tables" toml:"ignore-tables" yaml:"ignore-tables"`
	// IgnoreDBs is a blacklist of schemas.
	IgnoreDBs []string `json:"ignore-dbs" toml:"ignore-dbs" yaml:"ignore-dbs"`
}

// ToLower convert all entries to lowercase
// Deprecated: use `filter.CaseInsensitive` instead.
func (r *MySQLReplicationRules) ToLower() {
	if r == nil {
		return
	}

	for _, table := range r.DoTables {
		table.Name = strings.ToLower(table.Name)
		table.Schema = strings.ToLower(table.Schema)
	}
	for _, table := range r.IgnoreTables {
		table.Name = strings.ToLower(table.Name)
		table.Schema = strings.ToLower(table.Schema)
	}
	for i, db := range r.IgnoreDBs {
		r.IgnoreDBs[i] = strings.ToLower(db)
	}
	for i, db := range r.DoDBs {
		r.DoDBs[i] = strings.ToLower(db)
	}
}

type schemasFilter struct {
	schemas []string
}

func (f schemasFilter) MatchTable(schema string, table string) bool {
	return f.MatchSchema(schema)
}

func (f schemasFilter) MatchSchema(schema string) bool {
	i := sort.SearchStrings(f.schemas, schema)
	return i < len(f.schemas) && f.schemas[i] == schema
}

func (f schemasFilter) toLower() Filter {
	loweredSchemas := make([]string, 0, len(f.schemas))
	for _, schema := range f.schemas {
		loweredSchemas = append(loweredSchemas, strings.ToLower(schema))
	}
	sort.Strings(loweredSchemas)
	return schemasFilter{schemas: loweredSchemas}
}

// NewSchemasFilter creates a filter which only accepts a list of schemas.
func NewSchemasFilter(schemas ...string) schemasFilter {
	sortedSchemas := append([]string(nil), schemas...)
	sort.Strings(sortedSchemas)
	return schemasFilter{schemas: sortedSchemas}
}

type tablesFilter struct {
	tables []Table
}

func (f tablesFilter) MatchTable(schema string, table string) bool {
	tbl := Table{Schema: schema, Name: table}
	idx := sort.Search(len(f.tables), func(i int) bool {
		return !f.tables[i].lessThan(&tbl)
	})
	return idx < len(f.tables) && f.tables[idx] == tbl
}

func (f tablesFilter) MatchSchema(schema string) bool {
	tbl := Table{Schema: schema, Name: ""}
	idx := sort.Search(len(f.tables), func(i int) bool {
		return !f.tables[i].lessThan(&tbl)
	})
	return idx < len(f.tables) && f.tables[idx].Schema == schema
}

func (f tablesFilter) toLower() Filter {
	loweredTables := make([]Table, 0, len(f.tables))
	for _, table := range f.tables {
		loweredTables = append(loweredTables, Table{
			Schema: strings.ToLower(table.Schema),
			Name:   strings.ToLower(table.Name),
		})
	}
	res := tablesFilter{tables: loweredTables}
	sort.Sort(res)
	return res
}

func (tables tablesFilter) Len() int {
	return len(tables.tables)
}

func (tables tablesFilter) Less(i, j int) bool {
	return tables.tables[i].lessThan(&tables.tables[j])
}

func (tables tablesFilter) Swap(i, j int) {
	tables.tables[i], tables.tables[j] = tables.tables[j], tables.tables[i]
}

// NewTablesFilter creates a filter which only accepts a list of tables.
func NewTablesFilter(tables ...Table) Filter {
	res := tablesFilter{tables: append([]Table(nil), tables...)}
	sort.Sort(res)
	return res
}

// bothFilter is a filter which passes if both filters in the field passes.
type bothFilter struct {
	a Filter
	b Filter
}

func (f *bothFilter) MatchTable(schema string, table string) bool {
	return f.a.MatchTable(schema, table) && f.b.MatchTable(schema, table)
}

func (f *bothFilter) MatchSchema(schema string) bool {
	return f.a.MatchSchema(schema) && f.b.MatchSchema(schema)
}

func (f *bothFilter) toLower() Filter {
	return &bothFilter{
		a: f.a.toLower(),
		b: f.b.toLower(),
	}
}

var legacyWildcardReplacer = strings.NewReplacer(
	`\*`, ".*",
	`\?`, ".",
	`\[!`, "[^",
	`\[`, "[",
	`\]`, "]",
)

func matcherFromLegacyPattern(pattern string) (matcher, error) {
	if len(pattern) == 0 {
		return nil, errors.New("pattern cannot be empty")
	}
	if pattern[0] == '~' {
		// this is a regexp pattern.
		return newRegexpMatcher(pattern[1:])
	}

	if !strings.ContainsAny(pattern, "?*[") {
		// this is a literal string.
		return stringMatcher(pattern), nil
	}

	// this is a wildcard.
	pattern = "(?s)" + legacyWildcardReplacer.Replace(regexp.QuoteMeta(pattern))
	return newRegexpMatcher(pattern)
}

// ParseMySQLReplicationRules constructs up to 2 filters from the MySQLReplicationRules.
// Tables have to pass *both* filters to be processed.
func ParseMySQLReplicationRules(rules *MySQLReplicationRules) (Filter, error) {
	schemas := rules.DoDBs
	positive := true
	rulesLen := len(schemas)
	if rulesLen == 0 {
		schemas = rules.IgnoreDBs
		positive = false
		rulesLen = len(schemas) + 1
	}

	schemaRules := make([]rule, 0, rulesLen)
	for _, schema := range schemas {
		m, err := matcherFromLegacyPattern(schema)
		if err != nil {
			return nil, err
		}
		schemaRules = append(schemaRules, rule{
			schema:   m,
			table:    trueMatcher{},
			positive: positive,
		})
	}
	if !positive {
		schemaRules = append(schemaRules, rule{
			schema:   trueMatcher{},
			table:    trueMatcher{},
			positive: true,
		})
	}

	tables := rules.DoTables
	positive = true
	rulesLen = len(tables)
	if len(tables) == 0 {
		tables = rules.IgnoreTables
		positive = false
		rulesLen = len(tables) + 1
	}

	tableRules := make([]rule, 0, rulesLen)
	for _, table := range tables {
		sm, err := matcherFromLegacyPattern(table.Schema)
		if err != nil {
			return nil, err
		}
		tm, err := matcherFromLegacyPattern(table.Name)
		if err != nil {
			return nil, err
		}
		tableRules = append(tableRules, rule{
			schema:   sm,
			table:    tm,
			positive: positive,
		})
	}
	if !positive {
		tableRules = append(tableRules, rule{
			schema:   trueMatcher{},
			table:    trueMatcher{},
			positive: true,
		})
	}

	return &bothFilter{a: filter(schemaRules), b: filter(tableRules)}, nil
}
