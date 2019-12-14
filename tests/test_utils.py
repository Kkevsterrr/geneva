import sys
import pytest
# Include the root of the project
sys.path.append("..")

import actions.action
import actions.strategy
import actions.utils
import actions.duplicate

import logging

logger = logging.getLogger("test")


def get_test_configs():
    """
    Sets up the tests
    """
    tests = [
            ("both", True, ['DuplicateAction', 'DropAction', 'SleepAction', 'TraceAction', 'TamperAction', 'FragmentAction']),
            ("in", True, ['DropAction', 'TamperAction', 'SleepAction']),
            ("out", True, ['DropAction', 'TamperAction', 'TraceAction', 'SleepAction', 'DuplicateAction', 'FragmentAction']),
            ("both", False, ['DuplicateAction', 'SleepAction', 'TamperAction', 'FragmentAction']),
            ("in", False, ['TamperAction', 'SleepAction']),
            ("out", False, ['TamperAction', 'SleepAction', 'DuplicateAction', 'FragmentAction']),
    ]
    # To ensure caching is not breaking anything, double the tests
    return tests + tests


@pytest.mark.parametrize("direction,allow_terminal,supported_actions", get_test_configs())
def test_get_actions(direction, allow_terminal, supported_actions):
    """
    Tests the duplicate action primitive.
    """
    collected_actions = actions.action.Action.get_actions(direction, allow_terminal=allow_terminal)
    names = []
    for name, action_class in collected_actions:
        names.append(name)
    assert set(names) == set(supported_actions)
    assert len(names) == len(supported_actions)
