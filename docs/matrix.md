# Matrix Query Expansion

The CLI supports **matrix expansion** for efficiently testing multiple authorization scenarios in a single command.

## Syntax

Matrix queries use special syntax to generate multiple permission check variations:

### Pipe Operator `|` - Simple Alternatives

Use pipes to specify alternative values for any field:

```bash
treetop-cli check --principal alice|bob --action view|edit --resource-type Photo --resource-id photo1.jpg --detailed
```

This generates 4 separate queries:

1. alice → view → photo1.jpg
2. alice → edit → photo1.jpg
3. bob → view → photo1.jpg
4. bob → edit → photo1.jpg

All results are shown in a table with descriptive Query IDs:

```bash
┌─────┬──────────────────┬────────────┬──────────┬──────────────┐
│ #   │ QID              │ Status     │ Decision │ Policy ID    │
├─────┼──────────────────┼────────────┼──────────┼──────────────┤
│ 1   │ alice|view#0     │ ✓ Allowed  │ Allow    │ permit_1     │
│ 2   │ alice|edit#1     │ ✓ Allowed  │ Deny     │ forbid_1     │
│ 3   │ bob|view#2       │ ✗ Denied   │ Deny     │ (no match)   │
│ 4   │ bob|edit#3       │ ✗ Denied   │ Deny     │ (no match)   │
└─────┴──────────────────┴────────────┴──────────┴──────────────┘
```

### Bracket Notation `[]` - Cedar Entity Groups

Use square brackets to specify Cedar entity group membership:

```bash
treetop-cli check \
  --principal "DNS::User::alice[admins|webmasters]" \
  --action create_host \
  --resource-type Host \
  --resource-id myserver.example.com
```

This generates 2 queries:

1. DNS::User::alice[admins]
2. DNS::User::alice[webmasters]

Brackets preserve Cedar syntax and can include commas for compound groups:

```bash
--principal "alice[admins|webmasters,users]"
```

Generates:

1. `alice[admins]`
2. `alice[webmasters,users]`

## Large Matrices

The CLI automatically displays expansion preview for matrices with multiple permutations:

```bash
treetop-cli check \
  --principal alice|bob|charlie \
  --action view|edit|delete|create_host \
  --resource-type Photo \
  --resource-id photo1.jpg|photo2.jpg
```

Output:

```bash
Matrix: Generating 24 permutations: 3 principals × 4 actions × 2 resource-ids
```

This creates 3 × 4 × 2 = 24 separate authorization queries (2 resources fixed per line).

## Query ID Format

Each generated query gets a descriptive ID showing what permutation is being tested, and only includes varying fields.

## Escaping Special Characters

To include literal pipes or brackets in values, use backslash escaping:

```bash
# Literal pipe in resource ID
--resource-id "file\|with\|pipes.txt"

# Literal bracket in attribute value
--resource-attribute metadata="value[with]brackets"
```

## Attributes with Multiple Values

Attributes also support alternatives:

```bash
treetop-cli check \
  --principal alice|bob \
  --action view \
  --resource-type Document \
  --resource-id doc1 \
  --resource-attribute department="sales|engineering|finance"
```

This generates 2 × 3 = 6 queries (principals × department values).

## Output Format

By default, matrices automatically enable table display for readability. To force JSON output:

```bash
treetop-cli check \
  --principal alice|bob \
  --action view|edit \
  --resource-type Photo \
  --resource-id photo1.jpg \
  --json  # Forces JSON instead of table
```

## Examples

### Test Permission Across User Groups

```bash
treetop-cli check \
  --principal "user::alice[admin|moderator|viewer]" \
  --action "view" \
  --resource-type "Document" \
  --resource-id "sensitive-report.pdf"
```

### Test All CRUD Operations

```bash
treetop-cli check \
  --principal alice \
  --action "create|read|update|delete" \
  --resource-type "User" \
  --resource-id "user@example.com"
```

### Test Multiple Resources and Principals

```bash
treetop-cli check \
  --principal alice|bob|charlie \
  --action "edit" \
  --resource-type "Photo" \
  --resource-id "vacation.jpg|portrait.jpg|sunset.jpg"
```

## Limitations

- Matrix expansion only works in the `check` command
- Cartesian product can create very large query sets (use cautiously with large matrices)
- Preview shows count, but confirmation must be implicit (batch is executed immediately)
- Entity types must remain consistent (mixing principal types is not supported)
