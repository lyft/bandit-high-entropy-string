# bandit-high-entropy-string

A bandit plugin that looks for high entropy hardcoded strings (secrets).

This plugin exposes four new tests:

1. *high\_entropy\_assign*: Checks for secrets in assignment statements: `target = 'candidate'`
2. *high\_entropy\_funcarg*: Checks for secrets in function arguments: `caller('candidate', target='candidate'):`
3. *high\_entropy\_funcdef*: Checks for secrets in function definitions: `def caller('candidate', target='candidate'):`
4. *high\_entropy\_iter*: Checks for secrets in iterables (lists, tuples, dicts): `['candidate',
'candidate'] or ('candidate', 'candidate') or {'target': 'candidate'}`

## Installation

First you'll need to install bandit (note that in bandit-high-entropy-string
version 2.0 and higher you'll need to run bandit version 1.0 or higher):

```bash
virtualenv venv
source venv/bin/activate
pip install bandit
```

Then you can install the plugin:

```bash
pip install bandit-high-entropy-string
```

## Configuration

In your bandit.yaml config file, add the tests for inclusion:

```yaml
# Backwards compatible configuration for using profiles (only needed if you
# were previously using profiles and need to keep compatibility)
profiles:
    Secrets:
        include:
            - high_entropy_assign
            - high_entropy_funcarg
            - high_entropy_funcdef
            - high_entropy_iter

# Test inclusion for newer versions of bandit
tests:
  # high_entropy_funcdef
  - BHES100
  # high_entropy_funcarg
  - BHES101
  # high_entropy_iter
  - BHES102
  # high_entropy_assign
  - BHES103
```

You can also add extra configuration for each test (in the same config file):

```
# Configuration for each test (can be configured for each of the four tests)

high_entropy_assign:
    # Regex patterns to completely ignore for this test
    patterns_to_ignore:
      - 'public_key_.*'
    # Regex patterns to lower confidence for
    entropy_patterns_to_discount
      - 'maybe_public_key_.*'
```

## Running the tests

To run the tests, call bandit against your code base, specifying the profile:

```
$ bandit -r ./myapplication
```

## Contributing

### Code of conduct

This project is governed by [Lyft's code of
conduct](https://github.com/lyft/code-of-conduct).
All contributors and participants agree to abide by its terms.

### Sign the Contributor License Agreement (CLA)

We require a CLA for code contributions, so before we can accept a pull request
we need to have a signed CLA. Please [visit our CLA
service](https://oss.lyft.com/cla)
follow the instructions to sign the CLA.

### How it works and how to help

The plugin captures portions of the AST, generates Candidate objects and sends
them into the _report function. If a Candidate object's confidence is greater
than 0, it's reported. We nudge the confidence and severity based on criterea:

1. Flags (ENTROPY_PATTERNS_TO_FLAG). Any Candidate that matches any regex in this
   list is automatically flagged as confidence/severity 3/3. If there's secret
   patterns you know conclusively are secrets, add them here.
2. Discounts (ENTROPY_PATTERNS_TO_DISCOUNT). Any Candidate that matches a regex in
   this list is discounted. If the Candidate matches multiple regexes in this
   list, it may be discounted further. This discount is used in the confidence
   calculation.
3. Secret hints (LOW_SECRET_HINTS, HIGH_SECRET_HINTS). If any target or caller
   matches a regex in these lists then it will be used as a hint that a
   Candidate is a secret. This hint is used in the confidence and severity
   calculations. LOW_SECRET_HINTS leads to a lower confidence increase and
   HIGH_SECRET_HINTS leads to a higher confidence increase.
4. Safe functions (SAFE_FUNCTION_HINTS). Any Candidate that has a caller that
   matches any string in this list will will be discounted. This is used in the
   confidence calculation.
5. Entropy. If a Candidate's confidence level can be more accurately gauged by
   a strings level of entropy, we calculate it and if the string has high
   entropy its confidence level is increased. This calculation is avoided if
   possible, as it's relatively expensive.

The concept is to eliminate noise while more easily identifying Candidates that
may be secrets. Some help we'd love to have:

1. Help with the discount regex list. The regexes in the list often match too
   much and there aren't enough that match common python strings.
2. Help with the safe functions list (and the way we match the safe functions).
   There's a lot of python functions that rarely include secrets but often
   contain high entropy strings. We currently don't identify these function
   calls very well, which leads to higher noise.
3. Add and improve string captures. We're not currently capturing all available strings
   in the AST and for some string captures we aren't capturing them as
   efficiently as we could. For instance with dicts, we capture info like:
   {'target': 'candidate'}, but don't capture: {'target': 'target': 'candidate'},
   which could lead to better categorization.

Feel free to submit issues and pull requests for anything else you think would be useful
as well.
