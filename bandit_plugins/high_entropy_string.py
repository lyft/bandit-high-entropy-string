# -*- coding:utf-8 -*-

import ast
import logging
import sys

from high_entropy_string import PythonStringData

import bandit
from bandit.core import test_properties as test

logger = logging.getLogger(__name__)


def gen_config(name):
    """
    Default configuration for available configuration options.
    """
    if name == 'patterns_to_ignore' or name == 'entropy_patterns_to_discount':
        return []


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
                string_data = PythonStringData(
                    string=val.s,
                    target=target,
                    node_type='argument',
                    patterns_to_ignore=config.get('patterns_to_ignore'),
                    entropy_patterns_to_discount=config.get(
                        'entropy_patterns_to_discount'
                    )
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
            string_data = PythonStringData(
                string=kw.value.s,
                target=kw.arg,
                caller=caller,
                node_type='kwargument',
                patterns_to_ignore=config.get('patterns_to_ignore'),
                entropy_patterns_to_discount=config.get(
                    'entropy_patterns_to_discount'
                )
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
                    string_data = PythonStringData(
                        string=arg.s,
                        caller=caller,
                        target=target,
                        node_type='argument',
                        patterns_to_ignore=config.get('patterns_to_ignore'),
                        entropy_patterns_to_discount=config.get(
                            'entropy_patterns_to_discount'
                        )
                    )
                    strings.append(string_data)
    else:
        for arg in node.args:
            if isinstance(arg, ast.Str):
                string_data = PythonStringData(
                    string=arg.s,
                    caller=caller,
                    node_type='argument',
                    patterns_to_ignore=config.get('patterns_to_ignore'),
                    entropy_patterns_to_discount=config.get(
                        'entropy_patterns_to_discount'
                    )
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
            string_data = PythonStringData(
                string=val.s,
                target=target,
                node_type='dict',
                patterns_to_ignore=config.get('patterns_to_ignore'),
                entropy_patterns_to_discount=config.get(
                    'entropy_patterns_to_discount'
                )
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
                    string_data = PythonStringData(
                        string=string,
                        target=target,
                        node_type='assignment',
                        patterns_to_ignore=config.get('patterns_to_ignore'),
                        entropy_patterns_to_discount=config.get(
                            'entropy_patterns_to_discount'
                        )
                    )
                    strings.append(string_data)
            except AttributeError:
                string_data = PythonStringData(
                    string=string,
                    node_type='assignment',
                    patterns_to_ignore=config.get('patterns_to_ignore'),
                    entropy_patterns_to_discount=config.get(
                        'entropy_patterns_to_discount'
                    )
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
            string_data = PythonStringData(
                string=node.s,
                target=target,
                node_type='assignment',
                patterns_to_ignore=config.get('patterns_to_ignore'),
                entropy_patterns_to_discount=config.get(
                    'entropy_patterns_to_discount'
                )
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
            string_data = PythonStringData(
                string=string,
                target=node.s,
                node_type='assignment',
                patterns_to_ignore=config.get('patterns_to_ignore'),
                entropy_patterns_to_discount=config.get(
                    'entropy_patterns_to_discount'
                )
            )
            return _report([string_data])
    elif isinstance(node.parent, ast.Compare):
        # looks for "target == 'candidate'"
        comp = node.parent
        if isinstance(comp.left, ast.Name):
            if isinstance(comp.comparators[0], ast.Str):
                string_data = PythonStringData(
                    string=comp.comparators[0].s,
                    target=comp.left.id,
                    node_type='comparison',
                    patterns_to_ignore=config.get('patterns_to_ignore'),
                    entropy_patterns_to_discount=config.get(
                        'entropy_patterns_to_discount'
                    )
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
                string_data = PythonStringData(
                    string=string,
                    caller=caller,
                    target=target,
                    node_type='assignment',
                    patterns_to_ignore=config.get('patterns_to_ignore'),
                    entropy_patterns_to_discount=config.get(
                        'entropy_patterns_to_discount'
                    )
                )
                strings.append(string_data)
        except AttributeError:
            string_data = PythonStringData(
                string=string,
                caller=caller,
                node_type='assignment',
                patterns_to_ignore=config.get('patterns_to_ignore'),
                entropy_patterns_to_discount=config.get(
                    'entropy_patterns_to_discount'
                )
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

        if type(string_data.string) is not unicode:
            string_data.string = string_data.string.decode(
                'utf-8',
                errors='replace'
            )
        string_data.string = string_data.string.encode(
            'ascii',
            errors='replace'
        )

        if len(string_data.string) > 12:
            secret_start = string_data.string[:4]
            secret_end = string_data.string[-4:]
            try:
                secret_start = secret_start
                secret_end = secret_end
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
            text=u'Possible hardcoded secret(s) {0}.'.format(', '.join(reports))
        )
