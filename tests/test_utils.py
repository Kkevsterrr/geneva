import sys
import pytest
# Include the root of the project
sys.path.append("..")

import actions.action
import actions.strategy
import actions.utils
import actions.duplicate


def get_test_configs():
    """
    Sets up the tests
    """
    tests = [
            ("both", True, ['DuplicateAction', 'TraceAction', 'DropAction', 'SleepAction', 'TamperAction', 'FragmentAction']),
            ("in", True, ['DropAction', 'TamperAction']),
            ("out", True, ['DropAction', 'TamperAction', 'SleepAction', 'TraceAction', 'DuplicateAction', 'FragmentAction']),
            ("both", False, ['DuplicateAction', 'SleepAction', 'TamperAction', 'FragmentAction']),
            ("in", False, ['TamperAction']),
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


def test_punish_no_engine(logger):
    """
    Tests that punish_fitness properly handles no engine
    """
    assert 100 == actions.utils.punish_fitness(100, logger, None)
    assert 100 == actions.utils.punish_complexity(100, logger, None)
    assert 100 == actions.utils.punish_unused(100, logger, None)


def test_write_fitness_error(logger):
    """
    Tests handling of write fitness error cases
    """
    with pytest.raises(ValueError):
        actions.utils.write_fitness("<thiswillfail>", None, None)


def test_skipstrat(logger):
    """
    Tests we can create and raise a SkipStrategyException
    """
    with pytest.raises(actions.utils.SkipStrategyException):
        raise actions.utils.SkipStrategyException("Skip this!", 100)


def test_import_plugin(logger):
    """
    Tries to import some plugins
    """
    assert actions.utils.import_plugin("http", "client")
