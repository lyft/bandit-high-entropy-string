# -*- coding:utf-8 -*-

import bandit
from bandit.core import test_properties as test

import ast
import re
import logging
import json
import sys
import mimetypes

import zxcvbn

mimetypes.init()
FILE_EXTENSIONS_MATCH = r'([a-zA-Z0-9\-_/\.]+{0})$'.format(
    '|[a-zA-Z0-9\-_/.]+'.join(mimetypes.types_map.keys()).replace('.', '\.')
)

ENTROPY_PATTERNS_TO_FLAG = [
    re.compile('AKIA'),
    re.compile('^mongodb://.*:.*@'),
    re.compile('BEGIN RSA PRIVATE KEY')
]

ENTROPY_PATTERNS_TO_DISCOUNT = [
    # secrets don't contain whitespace
    re.compile(r'\s+'),
    # secrets don't end with file extensions
    re.compile(FILE_EXTENSIONS_MATCH),
    # Example: example.org
    re.compile(r'^([a-z0-9\-]+\.)+(com|net|me|org)$'),
    # secrets don't contain domain names
    # Example: example.org
    re.compile(r'^([a-z0-9\-]+\.)+(com|net|me|org)$'),
    # secrets don't have host names
    # Example: my-cool-hostname
    re.compile(r'^[a-z]*(-[a-z]*)*$'),
    # secrets don't look like python imports
    # Example import a.b.Hello_World1
    re.compile(r'^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$'),
    # secrets don't look like python variable names
    # Example: my_fun_variable_name1
    re.compile(r'^[a-zA-Z0-9]+(_[a-zA-Z0-9]+)+$'),
    # secrets don't have absolute paths
    # Example /a/b/1-B_z.txt
    re.compile(r'^/[a-zA-Z0-9\-_/\.]+$'),
    # secrets don't have relative paths
    # Example a/b/1-B_z.txt
    re.compile(r'^[a-zA-Z0-9\-_/\.]+/$'),
    # secrets don't have flask routes
    # Example: /v1/<path:path> or /v1/user/<id>/group
    re.compile(r'<([a-z_]+:[a-z_]+|[a-z_]+)>/'),
    re.compile(r'/<([a-z_]+:[a-z_]+|[a-z_]+)>'),
    # secrets don't email addresses
    # Example: test+spam@example.com
    re.compile(r'^[a-zA-Z0-9_\-\+]+@[a-zA-Z0-9\-]+\.(com|net|me)$'),
    # secrets don't look like constants
    # Example: EXAMPLE_CONSTANT
    re.compile(r'^[A-Z]*(_[A-Z]*)*$'),
    # secrets don't look like session dict keys
    # Example: XSRF-TOKEN
    re.compile(r'^[A-Z]*(-[A-Z]*)*$'),
    # secrets don't look like URIs
    # Example: https://example.org
    re.compile(r'^[a-z]+://'),
    # secrets don't look like format strings
    # Example: {10!s}
    # TODO: consider false negatives
    re.compile(r'\{\d{0,2}\}'),
    # Example: {my_Var}
    # TODO: consider false negatives
    re.compile(r'\{[a-z]{1,10}[a-zA-Z0-9_]{0-10]\}'),
    # secrets don't look like headers,
    # Example: X-Forwarded-For
    re.compile(r'^[A-Z][a-z]*(-[A-Z][a-z]*)*$'),
    # secrets don't look like date formats
    # Example: %Y%m%dT%H%M%SZ
    re.compile(r'^(%[a-zA-Z\-]+)+$'),
    # secrets don't look like phone numbers
    # Example: +15555555555
    re.compile(r'\d\d\d\d\d\d\d\d\d\d$')
]
VAR_DISCOUNTS = [
    re.compile(r'format', re.IGNORECASE),
    re.compile(r'pattern', re.IGNORECASE),
]
SECRET_VAR_HINTS = [
    re.compile(r'[a-z0-9_\.]+key[a-z0-9_\.]*', re.IGNORECASE),
    re.compile(r'secret', re.IGNORECASE),
    re.compile(r'pass', re.IGNORECASE),
    re.compile(r'passwd', re.IGNORECASE),
    re.compile(r'password', re.IGNORECASE),
    re.compile(r'token', re.IGNORECASE),
    re.compile(r'tok', re.IGNORECASE),
    re.compile(r'tkn', re.IGNORECASE),
    re.compile(r'random', re.IGNORECASE),
    re.compile(r'login', re.IGNORECASE)
]
SAFE_SECRET_SOURCES = [
    'os.environ.get',
    'str_env'
]


class StringData(object):

    def __init__(
            self,
            string=None,
            assigned=False,
            node_type=None,
            comparison=False,
            target=None,
            caller=None):
        self.string = string
        self.assigned = assigned
        self.node_type = node_type
        self.comparison = comparison
        self.target = target
        self.caller = caller
        self.cache = {}

    @property
    def discounted_regex(self):
        for pattern in ENTROPY_PATTERNS_TO_DISCOUNT:
            if pattern.search(self.string):
                return pattern.pattern

    @property
    def discounted(self):
        return any(
            (pattern.search(self.string)
                for pattern
                in ENTROPY_PATTERNS_TO_DISCOUNT)
        )

    @property
    def flagged_regex(self):
        for pattern in ENTROPY_PATTERNS_TO_FLAG:
            if pattern.search(self.string):
                return pattern.pattern

    @property
    def flagged(self):
        return any(
            (pattern.search(self.string)
                for pattern
                in ENTROPY_PATTERNS_TO_FLAG)
        )

    @property
    def likely_secret(self):
        # TODO: make this additive
        if not self.target:
            return False
        return any(
            (pattern.search(self.target)
                for pattern
                in SECRET_VAR_HINTS)
        )

    @property
    def likely_safe(self):
        if not self.target:
            return False
        return any(
            (pattern.search(self.target)
                for pattern
                in VAR_DISCOUNTS)
        )

    @property
    def safe_secret_source(self):
        return self.caller in SAFE_SECRET_SOURCES

    @property
    def entropy(self):
        if self.cache.get('entropy'):
            return self.cache['entropy']
        try:
            entropy = zxcvbn.password_strength(self.string)['entropy']
        except UnicodeDecodeError:
            logging.warning(
                'Failed to get entropy due to unicode decode error.'
            )
            entropy = 0
        except OverflowError:
            logging.warning(
                'Failed to get entropy due to overflow error.'
            )
            entropy = 0
        self.cache['entropy'] = entropy
        return self.cache['entropy']

    @property
    def entropy_per_char(self):
        try:
            return self.entropy/float(len(self.string))
        except ZeroDivisionError:
            return 0

    @property
    def confidence(self):
        if self.flagged:
            return 3
        if len(self.string) == 0:
            return 0
        confidence = 0
        if len(self.string) < 5:
            confidence -= 1
        if self.likely_secret:
            confidence += 2
        if (self.entropy > 80 or
                (self.entropy > 40 and self.entropy_per_char > 3)):
            confidence += 1
        if self.entropy >= 120:
            confidence += 1
        if self.discounted:
            confidence -= 2
        if self.safe_secret_source:
            confidence -= 1
        if self.likely_safe:
            confidence -= 1
        return confidence

    @property
    def severity(self):
        if self.flagged:
            return 3
        severity = self.confidence
        if self.likely_secret:
            severity += 1
        return severity

    def __str__(self):
        return json.dumps({
            'string_data.string': self.string,
            'string_data.discounted': self.discounted,
            'string_data.discounted_regex': self.discounted_regex,
            'string_data.flagged': self.discounted,
            'string_data.flagged_regex': self.flagged_regex,
            'string_data.entropy': self.entropy,
            'string_data.entropy_per_char': self.entropy_per_char,
            'string_data.likely_secret': self.likely_secret,
            'string_data.node_type': self.node_type,
            'string_data.safe_secret_source': self.safe_secret_source,
        })


@test.checks('FunctionDef')
def high_entropy_funcdef(context):
    # looks for "def function(some_arg='candidate')"

    # this pads the list of default values with "None" if nothing is given
    defs = [None] * (len(context.node.args.args) -
                     len(context.node.args.defaults))
    defs.extend(context.node.args.defaults)

    strings = []
    # go through all (param, value)s and look for candidates
    for key, val in zip(context.node.args.args, defs):
        if isinstance(key, ast.Name):
            target = key.arg if sys.version_info.major > 2 else key.id  # Py3
            if isinstance(val, ast.Str):
                string_data = StringData(
                    string=val.s,
                    target=target,
                    node_type='argument'
                )
                strings.append(string_data)
    return _report(strings)


@test.checks('Call')
def high_entropy_funcarg(context):
    # looks for "function('candidate', some_arg='candidate')"
    node = context.node
    strings = []
    try:
        caller = node.func.id
    except AttributeError:
        caller = None
    for kw in node.keywords:
        if isinstance(kw.value, ast.Str):
            string_data = StringData(
                string=kw.value.s,
                target=kw.arg,
                caller=caller,
                node_type='kwargument'
            )
            strings.append(string_data)
    if isinstance(node.parent, ast.Assign):
        for targ in node.parent.targets:
            try:
                target = targ.id
            except AttributeError:
                target = None
            for arg in node.args:
                if isinstance(arg, ast.Str):
                    string_data = StringData(
                        string=arg.s,
                        caller=caller,
                        target=target,
                        node_type='argument'
                    )
                    strings.append(string_data)
    else:
        for arg in node.args:
            if isinstance(arg, ast.Str):
                string_data = StringData(
                    string=arg.s,
                    caller=caller,
                    node_type='argument'
                )
                strings.append(string_data)
    return _report(strings)


def _get_assign(node):
    if isinstance(node, ast.Assign):
        return node
    else:
        return _get_assign(node.parent)


@test.checks('Dict')
def high_entropy_dict(context):
    node = context.node
    # looks for "some_string = {'target': 'candidate'}"
    _dict = dict(zip(node.keys, node.values))
    strings = []
    for key, val in _dict.iteritems():
        if isinstance(key, ast.Str):
            target = key.s
        if isinstance(key, ast.Name):
            target = key.id
        else:
            target = None
        if not isinstance(val, ast.Str):
            continue
        string_data = StringData(
            string=val.s,
            target=target,
            node_type='dict'
        )
        strings.append(string_data)
    return _report(strings)


@test.checks('Str')
def high_entropy_assign(context):
    node = context.node
    if isinstance(node.parent, ast.Assign):
        strings = []
        # looks for "some_var='candidate'"
        for targ in node.parent.targets:
            try:
                target = targ.id
            except AttributeError:
                target = None
            string_data = StringData(
                string=node.s,
                target=target,
                node_type='assignment'
            )
            strings.append(string_data)
        return _report(strings)
    elif isinstance(node.parent, ast.Index):
        # looks for "dict[target]='candidate'"
        # assign -> subscript -> index -> string
        assign = node.parent.parent.parent
        if isinstance(assign, ast.Assign):
            if isinstance(assign.value, ast.Str):
                string = assign.value.s
            elif isinstance(assign.value, ast.Name):
                string = assign.value.id
            else:
                return
            string_data = StringData(
                string=string,
                target=node.s,
                node_type='assignment'
            )
            return _report([string_data])
    elif isinstance(node.parent, ast.Compare):
        # looks for "target == 'candidate'"
        comp = node.parent
        if isinstance(comp.left, ast.Name):
            if isinstance(comp.comparators[0], ast.Str):
                string_data = StringData(
                    string=comp.comparators[0].s,
                    target=comp.left.id,
                    node_type='comparison'
                )
                return _report([string_data])
    elif isinstance(node.parent, ast.Attribute):
        # looks for "target == 'candidate{0}'.format('some_string')"
        strings = []
        if isinstance(node.parent.value, ast.Str):
            string = node.parent.value.s
        elif isinstance(node.parent.value, ast.Name):
            string = node.parent.value.id
        else:
            return
        try:
            caller = node.parent.attr
        except AttributeError:
            caller = None
        try:
            assign = _get_assign(node.parent)
            for targ in assign.targets:
                try:
                    target = targ.id
                except AttributeError:
                    target = None
                string_data = StringData(
                    string=string,
                    caller=caller,
                    target=target,
                    node_type='assignment'
                )
                strings.append(string_data)
        except AttributeError:
            string_data = StringData(
                string=string,
                caller=caller,
                node_type='assignment'
            )
            strings.append(string_data)
        return _report(strings)
    elif (isinstance(node.parent, ast.List) or
            isinstance(node.parent, ast.Tuple) or
            isinstance(node.parent, ast.Set)):
        # looks for "target = ['candidate', 'candidate']"
        strings = []
        try:
            assign = _get_assign(node.parent)
            for targ in assign.targets:
                try:
                    target = targ.id
                except AttributeError:
                    target = None
                string_data = StringData(
                    string=node.s,
                    target=target,
                    node_type='assignment'
                )
                strings.append(string_data)
        except AttributeError:
            string_data = StringData(
                string=node.s,
                node_type='assignment'
            )
            strings.append(string_data)
        return _report(strings)
    # TODO: Handle BinOp
    # TODO: Handle Return


def _report(strings):
    reports = []
    for string_data in strings:
        if string_data.confidence == 1:
            confidence = bandit.LOW
        elif string_data.confidence == 2:
            confidence = bandit.MEDIUM
        elif string_data.confidence >= 3:
            confidence = bandit.HIGH
        if string_data.severity == 1:
            severity = bandit.LOW
        elif string_data.severity == 2:
            severity = bandit.MEDIUM
        elif string_data.severity >= 3:
            severity = bandit.HIGH

        if len(string_data.string) > 12:
            secret = '\'{0!s}...{1!s}\''.format(
                string_data.string[:4], string_data.string[-4:]
            )
        else:
            secret = string_data.string
        if string_data.confidence >= 1:
            reports.append(secret)
    if reports:
        return bandit.Issue(
            severity=severity,
            confidence=confidence,
            text='Possible hardcoded secret(s) {0}.'.format(', '.join(reports))
        )
