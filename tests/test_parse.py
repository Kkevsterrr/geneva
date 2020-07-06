import pytest
import sys
# Include the root of the project
sys.path.append("..")

import actions.strategy
import actions.utils
import library


EDGE_CASES = [
              "[TCP:flags:A]-| \/",
              "\/ [TCP:flags:A]-|",
              "[TCP:flags:A]-duplicate(duplicate(duplicate(duplicate,),),)-| \/",
              "[IP:version:4]-| \/",
              "[TCP:flags:A]-duplicate(tamper{TCP:flags:corrupt}(duplicate(duplicate,),),)-| \/",
              "[TCP:flags:A]-tamper{TCP:flags:replace:S}(duplicate,)-| \/",
              # --- Tamper value tests ---
              # Tamper value should an empty string
              "[IP:frag:0]-fragment{tcp:-1:False}(drop,tamper{TCP:options-altchksum:replace:})-| \/",

              # Tamper value should be "074" and be a string
              "[IP:ihl:0]-fragment{tcp:-1:True}(duplicate,tamper{IP:load:replace:074})-| \/"
]


def get_tests():
    """
    Returns a list of tuples of tests of combinations of solutions and censors.
    """
    tests = []
    for solution in library.LAB_STRATEGIES:
        tests.append(solution["strategy"])

    for strategy in EDGE_CASES:
        tests.append(strategy)

    return tests


@pytest.mark.parametrize("solution", get_tests())
def test_library(solution, logger):
    """
    Pulls each solution from the solution library and tests it against
    it's corresponding censor to confirm the solution works.
    """
    # Parse the string representation of the solution
    strat = actions.utils.parse(solution, logger)
    logger.info("Parsed strategy %s" % (str(strat)))

    # Confirm the parsing was correct
    assert str(strat).strip() == solution, "Failed to correctly parse given strategy"

def test_quotes(logger):
    """
    Tests that it properly handles strategies with leading/ending quotes.
    """
    assert "\/" == str(actions.utils.parse("\"\/\"", logger)).strip()
    assert "\/ [TCP:flags:A]-drop-|" == str(actions.utils.parse("\"\/ [TCP:flags:A]-drop-|\"", logger)).strip()

def test_failures(logger):
    """
    Tests that properly fails to parse strategies
    """

    with pytest.raises(actions.tree.ActionTreeParseError):
        actions.utils.parse("asdfasdf", logger)

    with pytest.raises(actions.tree.ActionTreeParseError):
        actions.utils.parse("[]-asdfasdf", logger)

    # Field doesn't exist
    with pytest.raises(AssertionError):
        actions.utils.parse("[TCP:thing:1]-nooooooope", logger)

    assert actions.utils.parse("", logger) is not None
    assert " \/ " == str(actions.utils.parse("", logger))
