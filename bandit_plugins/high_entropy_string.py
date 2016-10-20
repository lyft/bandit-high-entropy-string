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

logger = logging.getLogger(__name__)

# TODO: change caller logic to more accurately identify callers (like strftime
# vs .strftime vs datetime.datetime.strftime)

ENTROPY_PATTERNS_TO_FLAG = [
    # AWS access keys (which often have secret keys listed with them)
    re.compile('AKIA'),
    # URLs with username/password combos
    re.compile('^[a-z]+://.*:.*@'),
    # PEM encoded PKCS8 private keys
    re.compile('BEGIN.*PRIVATE KEY')
]
mimetypes.init()
EXTS = [re.escape(i) for i in mimetypes.types_map.keys()]
FILE_EXTENSIONS_MATCH = r'([a-zA-Z0-9\-_/\.]+{0})$'.format(
    r'|[a-zA-Z0-9\-_/.]+'.join(EXTS)
)
MIMETYPES_MATCH = re.escape(
    r'^({0})$'.format('|'.join(mimetypes.types_map.values()))
)

PATTERNS_TO_IGNORE = [
]

ENTROPY_PATTERNS_TO_DISCOUNT = [
    # secrets don't contain whitespace
    re.compile(r'\s+'),
    # secrets don't end with file extensions
    re.compile(FILE_EXTENSIONS_MATCH),
    # secrets don't look like mime types
    re.compile(MIMETYPES_MATCH),
    # secrets don't contain domain names
    # Example: example.org
    re.compile(r'^([a-z0-9\-]+\.)+(com|net|me|org|edu)$'),
    # secrets don't have host names
    # Example: my-cool-hostname
    re.compile(r'^[a-z]*(-[a-z]*)*$'),
    # secrets don't look like python imports
    # Example import a.b.Hello_World1
    re.compile(r'^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$'),
    # secrets don't look like python variable names
    # Example: my_fun_variable_name1
    re.compile(r'^_?_?[a-zA-Z0-9]+(_[a-zA-Z0-9]+)+$'),
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
    # secrets don't look like urls with args
    # Example: /a/b/c?hello=world&test=me
    re.compile(r'/[a-zA-Z\-_\.]+(/[a-zA-Z\-_\.])*\?[a-zA-Z\-_\.=&]$'),
    # secrets don't email addresses
    # Example: test+spam@example.com
    re.compile(r'[a-zA-Z0-9_\-\+]+@[a-zA-Z0-9\-]+\.(com|net|me|edu)'),
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
    re.compile(r'\{_?_?[a-zA-Z]{1,10}[a-zA-Z0-9_]{0,10}\}'),
    # secrets don't look like headers,
    # Example: X-Forwarded-For
    re.compile(r'^[A-Z][a-z]*(-[A-Z][a-z]*)*$'),
    # secrets don't look like date formats
    # Example: %Y%m%dT%H%M%SZ
    re.compile(r'^(%[a-zA-Z\-]+)+$'),
    # Example: 2012-10-17T00:00:00Z
    re.compile(r'\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ'),
    # Example: 2021-08-22
    re.compile(r'\d\d\d\d-\d\d-\d\d'),
    # secrets don't look like phone numbers
    # Example: +15555555555
    re.compile(r'\d\d\d\d\d\d\d\d\d\d$'),
    # secrets don't look cli arguments
    # Example: --test_me-please
    re.compile(r'^--[a-zA-Z0-9\-_]$'),
    # key-lookups
    # Example: my_var:b:c
    re.compile(r'^[a-zA-Z0-9_\-]+(:[a-zA-Z0-9_\-])+$')
]
LOW_SECRET_HINTS = [
    re.compile(r'[a-z0-9_\.]+key[a-z0-9_\.]*', re.IGNORECASE),
    re.compile(r'pw', re.IGNORECASE),
    re.compile(r'tok', re.IGNORECASE),
    re.compile(r'tkn', re.IGNORECASE),
    re.compile(r'random', re.IGNORECASE),
    re.compile(r'auth', re.IGNORECASE)
]
HIGH_SECRET_HINTS = [
    re.compile(r'secret', re.IGNORECASE),
    re.compile(r'pass', re.IGNORECASE),
    re.compile(r'passwd', re.IGNORECASE),
    re.compile(r'password', re.IGNORECASE),
    re.compile(r'login', re.IGNORECASE)
]
SAFE_VAR_HINTS = [
    re.compile(r'format', re.IGNORECASE),
    re.compile(r'pattern', re.IGNORECASE),
    re.compile(r'id', re.IGNORECASE),
    re.compile(r'user-agent', re.IGNORECASE)
]
SAFE_FUNCTION_HINTS = [
    'os.environ.get',
    'os.path.join',
    're.sub',
    're.search',
    're.split',
    're.compile',
    're.find',
    'datetime.datetime.strptime',
    'datetime.datetime.strftime',
    'time.strftime',
    '.strftime',
    '.strptime',
    'dateutil.parser.parse',
    'pytz.timezone',
    'hasattr',
    'getattr',
    'delattr',
    'statsd.timer',
    'timezone',
    'open',
    '.split',
    'csv.reader',
    'flask.request.json.get',
    'flask.request.args.get',
    'flask.request.form.get',
    'string.replace'
]


def gen_config(name):
    """
    Default configuration for available configuration options.
    """
    if name == 'patterns_to_ignore' or name == 'entropy_patterns_to_discount':
        return []


class StringData(object):

    def __init__(
            self,
            string=None,
            assigned=False,
            node_type=None,
            target=None,
            caller=None,
            config=None):
        self.string = string
        self.assigned = assigned
        self.node_type = node_type
        self.target = target
        self.caller = caller
        self.cache = {}
        if config is None:
            self.config = {}
        else:
            self.config = config

    @property
    def ignored(self):
        for pattern in PATTERNS_TO_IGNORE:
            if pattern.search(self.string):
                return True
        for _pattern in self.config.get('patterns_to_ignore', []):
            pattern = re.compile(_pattern)
            if pattern.search(self.string):
                return True

    @property
    def discounts_regex(self):
        if self.cache.get('discounts_regex') is not None:
            return self.cache['discounts_regex']
        patterns = []
        for pattern in ENTROPY_PATTERNS_TO_DISCOUNT:
            if pattern.search(self.string):
                patterns.append(pattern.pattern)
        for _pattern in self.config.get('entropy_patterns_to_discount', []):
            pattern = re.compile(_pattern)
            if pattern.search(self.string):
                patterns.append(pattern.pattern)
        self.cache['discounts_regex'] = patterns
        return self.cache['discounts_regex']

    @property
    def discounts(self):
        return len(self.discounts_regex)

    @property
    def flags_regex(self):
        if self.cache.get('flags_regex') is not None:
            return self.cache['flags_regex']
        patterns = []
        for pattern in ENTROPY_PATTERNS_TO_FLAG:
            if pattern.search(self.string):
                patterns.append(pattern.pattern)
        self.cache['flags_regex'] = patterns
        return self.cache['flags_regex']

    @property
    def flags(self):
        return len(self.flags_regex)

    @property
    def secret_rating(self):
        if self.cache.get('secret_rating') is not None:
            return self.cache['secret_rating']
        secret = 0
        if self.target:
            for pattern in LOW_SECRET_HINTS:
                if pattern.search(self.target):
                    secret += 1
            for pattern in HIGH_SECRET_HINTS:
                if pattern.search(self.target):
                    secret += 2
        self.cache['secret_rating'] = secret
        return self.cache['secret_rating']

    @property
    def safety_rating(self):
        if self.cache.get('safety_rating') is not None:
            return self.cache['safety_rating']
        safety = 0
        if self.target:
            for pattern in SAFE_VAR_HINTS:
                if pattern.search(self.target):
                    safety += 1
        if self.caller and self.caller in SAFE_FUNCTION_HINTS:
            safety += 2
        self.cache['safety_rating'] = safety
        return self.cache['safety_rating']

    @property
    def entropy(self):
        if self.cache.get('entropy') is not None:
            return self.cache['entropy']
        if not self.string:
            return 0
        if len(self.string) > 100:
            check_str = self.string[:100]
        else:
            check_str = self.string
        try:
            entropy = zxcvbn.password_strength(check_str)['entropy']
        except UnicodeDecodeError:
            logger.warning(
                'Failed to get entropy due to unicode decode error.'
            )
            entropy = 0
        except OverflowError:
            logger.warning(
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
        if self.cache.get('confidence') is not None:
            return self.cache['confidence']
        if self.flags > 0:
            return 3
        if len(self.string) == 0:
            return 0
        if self.ignored:
            return 0
        confidence = 0
        if self.secret_rating > 0:
            confidence += 1
        if self.secret_rating > 1:
            confidence += 2
        if len(self.string) < 5:
            confidence -= 1
        if self.discounts > 0:
            confidence -= 2
        if self.discounts > 2:
            confidence -= 1
        if self.safety_rating > 0:
            confidence -= 1
        if self.safety_rating > 1:
            confidence -= 1
        # Avoid entropy calculation if possible.
        if confidence > 2 or confidence < -1:
            return confidence
        if (self.entropy > 80 or
                (self.entropy > 40 and self.entropy_per_char > 3)):
            confidence += 1
        if self.entropy >= 120:
            confidence += 1
        self.cache['confidence'] = confidence
        return self.cache['confidence']

    @property
    def severity(self):
        if self.flags:
            return 3
        severity = self.confidence
        if self.secret_rating > 0:
            severity += 1
        if self.secret_rating > 1:
            severity += 1
        return severity

    def __str__(self):
        return json.dumps({
            'string_data.string': self.string,
            'string_data.discounts': self.discounted,
            'string_data.discounts_regex': self.discounts_regex,
            'string_data.flags': self.discounts,
            'string_data.flags_regex': self.flags_regex,
            'string_data.entropy': self.entropy,
            'string_data.entropy_per_char': self.entropy_per_char,
            'string_data.secret_rating': self.secret_rating,
            'string_data.safety_rating': self.safety_rating,
            'string_data.node_type': self.node_type
        })


@test.takes_config
@test.checks('FunctionDef')
@test.test_id('BHES100')
def high_entropy_funcdef(context, config):
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
                    node_type='argument',
                    config=config
                )
                strings.append(string_data)
    return _report(strings)


@test.takes_config
@test.checks('Call')
@test.test_id('BHES101')
def high_entropy_funcarg(context, config):
    # looks for "function('candidate', some_arg='candidate')"
    node = context.node
    strings = []
    try:
        caller = context.call_function_name_qual
    except AttributeError:
        caller = None
    for kw in node.keywords:
        if isinstance(kw.value, ast.Str):
            string_data = StringData(
                string=kw.value.s,
                target=kw.arg,
                caller=caller,
                node_type='kwargument',
                config=config
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
                        node_type='argument',
                        config=config
                    )
                    strings.append(string_data)
    else:
        for arg in node.args:
            if isinstance(arg, ast.Str):
                string_data = StringData(
                    string=arg.s,
                    caller=caller,
                    node_type='argument',
                    config=config
                )
                strings.append(string_data)
    return _report(strings)


def _get_assign(node):
    if isinstance(node, ast.Assign):
        return node
    else:
        return _get_assign(node.parent)


@test.takes_config
@test.checks('Dict')
@test.checks('List')
@test.checks('Tuple')
@test.checks('Set')
@test.test_id('BHES102')
def high_entropy_iter(context, config):
    node = context.node
    if isinstance(node, ast.Dict):
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
                node_type='dict',
                config=config
            )
            strings.append(string_data)
        return _report(strings)
    elif (isinstance(node, ast.List) or
            isinstance(node, ast.Tuple) or
            isinstance(node, ast.Set)):
        # looks for "target = ['candidate', 'candidate']"
        # looks for "target = ('candidate', 'candidate')"
        # looks for "target = set('candidate', 'candidate')"
        strings = []
        for etl in node.elts:
            if isinstance(etl, ast.Str):
                string = etl.s
            else:
                continue
            try:
                assign = _get_assign(node.parent)
                for targ in assign.targets:
                    try:
                        target = targ.id
                    except AttributeError:
                        target = None
                    string_data = StringData(
                        string=string,
                        target=target,
                        node_type='assignment',
                        config=config
                    )
                    strings.append(string_data)
            except AttributeError:
                string_data = StringData(
                    string=string,
                    node_type='assignment',
                    config=config
                )
                strings.append(string_data)
        return _report(strings)


@test.takes_config
@test.checks('Str')
@test.test_id('BHES103')
def high_entropy_assign(context, config):
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
                node_type='assignment',
                config=config
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
            else:
                return
            string_data = StringData(
                string=string,
                target=node.s,
                node_type='assignment',
                config=config
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
                    node_type='comparison',
                    config=config
                )
                return _report([string_data])
    elif isinstance(node.parent, ast.Attribute):
        # looks for "target == 'candidate{0}'.format('some_string')"
        strings = []
        if isinstance(node.parent.value, ast.Str):
            string = node.parent.value.s
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
                    node_type='assignment',
                    config=config
                )
                strings.append(string_data)
        except AttributeError:
            string_data = StringData(
                string=string,
                caller=caller,
                node_type='assignment',
                config=config
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
            secret_start = string_data.string[:4]
            secret_end = string_data.string[-4:]
            try:
                secret_start = secret_start.encode('utf-8')
                secret_end = secret_end.encode('utf-8')
            except (UnicodeDecodeError, UnicodeEncodeError):
                pass
            secret = '\'{0!s}...{1!s}\''.format(secret_start, secret_end)
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
