import logging
import pytest
import sys
# Include the root of the project
sys.path.append("..")

import censors.censor_driver
import library
import common


def get_censors():
    """
    Retrieves a list of all available censors for testing.
    """
    tests = []
    docker_censors = censors.censor_driver.get_censors()
    test_type = "echo"
    for censor in docker_censors.keys():
        # Skip the dummy censor
        if censor == "dummy":
            continue
        tests.append((censor, test_type))
    return tests


def get_tests():
    """
    Returns a list of tuples of tests of combinations of solutions and censors.
    """
    tests = []
    all_censors = censors.censor_driver.get_censors().keys()
    test_type = "echo"
    for solution in library.LAB_STRATEGIES:
        # Calculate the set of censors a solution does not beat
        defeated = set(all_censors) - set(solution["censors"])
        for censor in defeated:
            tests.append((solution["strategy"], censor, test_type))

    return tests


@pytest.mark.parametrize("censor, test_type", get_censors())
def test_censors(logger, censor, test_type):
    """
    Tests each censor against an empty strategy to confirm the censor works.
    """
    # Test each censor against an empty strategy.
    # \/ is an empty strategy, representing no input or output chains
    test_library(logger, "\/", censor, test_type)


@pytest.mark.skip()
@pytest.mark.parametrize("solution, censor, test_type", get_tests())
def test_library(logger, solution, censor, test_type):
    """
    Pulls each solution from the solution library and tests it against
    it's corresponding censor to confirm the censor wins.
    """
    if censor == "dummy":
        pytest.skip("Skipping dummy censor test.")
    fitness = common.run_test(logger, solution, censor, test_type, log_on_success=True)
    # If the fitness was less than 0, the strategy failed to beat the censor
    if fitness > 0:
        pytest.fail("Fitness was %d - strategy beat censor." % fitness)


def test_one_library(logger):
    """
    Runs a test using one solution from the library as a quick litmus
    test for code health.
    """
    solution = "\/ [TCP:dataofs:5]-drop-|"
    censor = "censor2"
    test_type = "echo"
    fitness = common.run_test(logger, solution, censor, test_type, log_on_fail=True)
    # If the fitness was less than 0, the strategy failed to beat the censor
    if fitness < 0:
        pytest.fail("Fitness was %d - censor beat strategy." % fitness)
