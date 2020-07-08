import subprocess
import sys
# Include the root of the project
sys.path.append("..")

import actions.strategy
import actions.utils
import evolve
import evaluator

import pytest


def run_test(logger, solution, censor, test_type, log_on_success=False, log_on_fail=False):
    """
    Tests a given solution against a given censor under a given test type
    using the given log level.
    """
    # Test if docker is running
    try:
        subprocess.check_output(['docker', 'ps'])
    except subprocess.CalledProcessError:
        pytest.fail("Docker is not running")

    try:
        # Parse the string representation of the solution
        strat = actions.utils.parse(solution, logger)
        logger.info("Parsed strategy %s" % (str(strat)))

        # Confirm the parsing was correct
        assert str(strat).strip() == solution, "Failed to correctly parse given strategy"

        logger.info("Testing %s" % censor)

        # Setup the external server to test with, if an http test is done
        if test_type == "echo":
            external_server = None
        elif test_type == "http":
            external_server = "facebook.com"

        # Create an evaluator
        cmd = [
            "--test-type", "echo",
            "--censor", censor,
            "--log", actions.utils.CONSOLE_LOG_LEVEL,
            "--no-skip-empty",
            "--bad-word", "facebook",
            "--output-directory", actions.utils.RUN_DIRECTORY
        ]
        if log_on_success:
            cmd += ["--log-on-success"]
        if log_on_fail:
            cmd += ["--log-on-fail"]
        tester = evaluator.Evaluator(cmd, logger)

        # Use the fitness function to evaluate the strategy
        population = evolve.fitness_function(logger, [strat], tester)

        # Check that we got back the same number of individuals we gave
        assert len(population) == 1, "Population size changed"

        # Shutdown the evaluator
        tester.shutdown()

        # Retrieve the fitness from the individual
        return population[0].fitness
    finally:
        clean_containers()


def clean_containers():
    """
    Cleans up the client_main, censor_main, and server_main containers used by the evaluator
    if it fails to.
    """
    for name in ["client", "censor", "server"]:
        try:
            subprocess.check_output(["docker", "stop", "%s_main" % name], stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            pass
        try:
            subprocess.check_output(["docker", "rm", "%s_main"], stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            pass
