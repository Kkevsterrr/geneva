import pytest
import sys
# Include the root of the project
sys.path.append("..")

import library
import common
import censors.censor_driver


def get_tests():
    """
    Returns a list of tuples of tests of combinations of solutions and censors.
    """
    tests = []
    test_type = "echo"
    for solution in library.LAB_STRATEGIES:
        for censor in solution["censors"]:
            tests.append((solution["strategy"], censor, test_type))

    return tests


@pytest.mark.parametrize("solution, censor, test_type", get_tests())
def test_library(logger, solution, censor, test_type):
    """
    Pulls each solution from the solution library and tests it against
    it's corresponding censor to confirm the solution works.
    """
    docker_censors = censors.censor_driver.get_censors()
    if censor not in docker_censors:
        pytest.skip("Censor %s is disabled." % censor)

    fitness = common.run_test(logger, solution, censor, test_type, log_on_fail=True)
    # If the fitness was less than 0, the strategy failed to beat the censor
    if fitness <= 0:
        pytest.fail("Fitness was %d - strategy failed to beat censor." % fitness)
