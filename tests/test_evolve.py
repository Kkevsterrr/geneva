import copy
import tempfile
import traceback
import os
import pytest
import sys
# Include the root of the project
sys.path.append("..")

import library
import common
import evolve
import evaluator
import actions.utils
import layers.packet
from actions.tamper import TamperAction
from scapy.all import IP, TCP, UDP
import random


def test_evolve(logger):
    """
    Work in Progress
    """
    strategies = []
    for strategy in library.LAB_STRATEGIES:
        strategies.append(strategy["strategy"])
    logger.setLevel("ERROR")
    options = {}
    options["non-unique-hall"] = False
    options["hall-size"] = 100000
    options["population_size"] = 500
    options["in-trees"] = 0
    options["out-trees"] = 1
    options["in-actions"] = 0
    options["out-actions"] = 3
    options["force_cleanup"] = False
    options["num_generations"] = 10
    options["seed"] = None
    options["elite_clones"] = 0
    options["allowed_retries"] = 20
    options["no-canary"] = True
    options["load_from"] = False
    options["disable_action"] = []
    hall = evolve.genetic_solve(logger, options, None)
    evolve.print_results(hall, logger)


def test_disable_single_action(logger):
     """
     Tests disabling a single action
     """
     layers.packet.Packet.reset_restrictions()
     try:
         logger.setLevel("ERROR")
         actions.action.ACTION_CACHE={}
         actions.action.ACTION_CACHE["in"] = {}
         actions.action.ACTION_CACHE["out"] = {}
         disable_actions=["fragment", "drop", "tamper", "duplicate"]
         for action in disable_actions:
             print("Testing disable %s" % (str(action)))
             for i in range(0, 2000):
                 p = evolve.generate_strategy(logger, 0, 2, 0, 4, None, disabled=[action])
                 assert str(action) not in str(p)
             actions.action.ACTION_CACHE={}
             actions.action.ACTION_CACHE["in"] = {}
             actions.action.ACTION_CACHE["out"] = {}
     finally:
         layers.packet.Packet.reset_restrictions()


def test_disable_multiple_actions(logger):
    """
    Tests disabling multiple actions
    """
    layers.packet.Packet.reset_restrictions()
    try:
        logger.setLevel("ERROR")
        actions.action.ACTION_CACHE={}
        actions.action.ACTION_CACHE["in"] = {}
        actions.action.ACTION_CACHE["out"] = {}
        disable_actions=["fragment", "drop", "tamper", "duplicate"]
        for num in range(0,10):
            action1 = disable_actions[random.randint(0,3)]
            action2 = disable_actions[random.randint(0,3)]
            action3 = disable_actions[random.randint(0,3)]
            action_list = [action1, action2, action3]
            print("Testing disable %s" % (str(action_list)))
            for i in range(0, 1000):
                p = evolve.generate_strategy(logger, 0, 2, 0, 4, None, disabled=action_list)
                assert str(action1) not in str(p)
                assert str(action2) not in str(p)
                assert str(action3) not in str(p)
            actions.action.ACTION_CACHE={}
            actions.action.ACTION_CACHE["in"] = {}
            actions.action.ACTION_CACHE["out"] = {}
    finally:
        layers.packet.Packet.reset_restrictions()


def assert_only(ind, field):
    """
    Helper method to assert that the only tamper field in a given
    individual is the given field.
    """
    for forest in [ind.in_actions, ind.out_actions]:
        for tree in forest:
            for action in tree:
                if isinstance(action, TamperAction):
                    assert action.field == field


def assert_not(ind, fields):
    """
    Helper method to assert that the tamper field in a given
    individual is not in the list of given fields.
    """
    for forest in [ind.in_actions, ind.out_actions]:
        for tree in forest:
            for action in tree:
                if isinstance(action, TamperAction):
                    assert action.field not in fields


@pytest.mark.parametrize("use_canary", [False, True], ids=["without_canary", "with_canary"])
def test_disable_fields(logger, use_canary):
    """
    Tests disabling fields.
    """
    # Restrict evolve to using ONLY the ack field in the TCP header
    try:
        evolve.restrict_headers(logger, "TCP", "ack", "")
        population = []
        print("Generating population pool")
        canary_id = None

        # Create an evaluator
        if use_canary:
            cmd = [
                "--test-type", "http",
                "--log", actions.utils.CONSOLE_LOG_LEVEL,
                "--use-external-sites",
                "--no-skip-empty",
                "--bad-word", "facebook",
                "--output-directory", actions.utils.RUN_DIRECTORY
            ]
            tester = evaluator.Evaluator(cmd, logger)
            canary_id = evolve.run_collection_phase(logger, tester)
            assert canary_id and canary_id != -1

        # Generate random strategies to initialize the population
        for i in range(0, 2000):
            p = evolve.generate_strategy(logger, 0, 2, 0, 4, None, environment_id=canary_id)
            assert_only(p, "ack")
            population.append(p)

        for generation in range(0, 20):
            print("Starting fake generation %d" % generation)
            for p in population:
                p.mutate(logger)
                assert_only(p, "ack")

        layers.packet.Packet.reset_restrictions()

        # Restrict evolve to using NOT the dataofs or chksum field in the TCP header
        evolve.restrict_headers(logger, "TCP,UDP", "", "dataofs,chksum",)
        population = []
        print("Generating population pool")
        canary_id = None
        # Create an evaluator
        if use_canary:
            cmd = [
                "--test-type", "http",
                "--log", actions.utils.CONSOLE_LOG_LEVEL,
                "--use-external-sites",
                "--no-skip-empty",
                "--bad-word", "facebook",
                "--output-directory", actions.utils.RUN_DIRECTORY
            ]
            tester = evaluator.Evaluator(cmd, logger)
            canary_id = evolve.run_collection_phase(logger, tester)
            assert canary_id and canary_id != -1

        # Generate random strategies to initialize the population
        for i in range(0, 2000):
            p = evolve.generate_strategy(logger, 0, 2, 0, 4, None, environment_id=canary_id)
            assert_not(p, ["dataofs", "chksum"])
            population.append(p)

        for generation in range(0, 20):
            print("Starting fake generation %d" % generation)
            for p in population:
                p.mutate(logger)
                assert_not(p, ["dataofs", "chksum"])

    finally:
        layers.packet.Packet.reset_restrictions()


@pytest.mark.parametrize("use_canary", [True, False], ids=["with_canary", "without_canary"])
def test_population_pool(logger, use_canary):
    """
    Creates a large population pool and runs them through packets.
    The goal of this test is to basically fuzz the framework (and scapy) without having
    to use the evaluator to do so to look for any exceptions/issues that may arise
    to catch them early.
    """
    logger.setLevel("ERROR")
    canary_id = None
    # Create an evaluator
    if use_canary:
        cmd = [
            "--test-type", "echo",
            "--censor", "censor2",
            "--log", actions.utils.CONSOLE_LOG_LEVEL,
            "--no-skip-empty",
            "--bad-word", "facebook",
            "--output-directory", actions.utils.RUN_DIRECTORY
        ]
        tester = evaluator.Evaluator(cmd, logger)
        canary_id = evolve.run_collection_phase(logger, tester)

    layers.packet.Packet.reset_restrictions()
    population = []
    print("Generating population pool")
    # Generate random strategies to initialize the population
    for i in range(0, 2000):
        p = evolve.generate_strategy(logger, 0, 2, 0, 4, None, environment_id=canary_id)
        population.append(p)
    print("Population pool generated")
    packets = [
        IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"),
        IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="SA"),
        IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="PA"),
        IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="SA"),
        IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="R"),
        IP(src="127.0.0.1", dst="127.0.0.1")/UDP(sport=2222, dport=3333, chksum=0x4444),
        IP(src="127.0.0.1", dst="127.0.0.1")/UDP(sport=2222, dport=3333, chksum=0x8888)
    ]
    packets = [layers.packet.Packet(packet) for packet in packets]
    for generation in range(0, 20):
        print("Starting fake generation %d" % generation)
        for ind in population:
            for packet in packets:
                try:
                    ind.act_on_packet(packet, logger)
                except:
                    traceback.print_exc()
                    print(str(ind))
                    print(packet)
                    packet.show()
                    print(layers.packet.SUPPORTED_LAYERS)
                    raise
        for p in population:
            try:
                p.mutate(logger)
            except:
                traceback.print_exc()
                print(str(p))
                print(packet)
                print(str(ind))
                raise


def test_eval_only(logger):
    """
    Tests eval-only.
    """
    cmd = [
        "--test-type", "http",
        "--censor", "censor2",
        "--server", "http://facebook.com",
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
        "--bad-word", "facebook",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    tester = evaluator.Evaluator(cmd, logger)

    strat = "\/"
    success_rate = evolve.eval_only(logger, strat, tester, runs=1)
    assert success_rate == 0
    with tempfile.NamedTemporaryFile() as f:
        f.write(str(strat).encode('utf-8'))
        f.flush()
        success_rate = evolve.eval_only(logger, f.name, tester, runs=1)
        assert success_rate == 0

    with tempfile.NamedTemporaryFile() as f:
        # If the file is empty, we should just return None
        assert not evolve.eval_only(logger, f.name, tester, runs=1)

    # Eval only with two successful strategies that are in a file
    strat = "\/ [TCP:flags:R]-drop-|"
    with tempfile.NamedTemporaryFile() as f:
        f.write(str(strat).encode('utf-8'))
        f.write(str(strat).encode('utf-8'))
        f.flush()
        success_rate = evolve.eval_only(logger, f.name, tester, runs=1)
        assert success_rate == 1


def test_mutation(logger):
    """
    Tests mutation.
    """

    layers.packet.Packet.reset_restrictions()
    population = [actions.utils.parse("[TCP:flags:PA]-| \/", logger)]
    population[0].in_enabled = False
    assert population
    assert str(actions.utils.parse(str(population[0]), logger)) == str(population[0])
    # Create a hall with a strategy that has failed 5x, but not yet 10x
    hall = { "[TCP:flags:PA]-drop-| \/ ": [-400] * 5 }
    options = {
        "cxpb": 0,
        "mutpb": 1,
    }
    for i in range(0, 2000):
        offspring = evolve.mutation_crossover(logger, population, hall, options)
        assert offspring
        print(offspring[0])
        if str(offspring[0]).strip() == "[TCP:flags:PA]-drop-| \/":
            print("Good mutation")
            break
    else:
        pytest.fail("Never mutated to test strategy")
    print("Rejecting future mutations to [TCP:flags:PA]-drop-| \\/ ")
    stred = str(actions.utils.parse("[TCP:flags:PA]-drop-| \/", logger))
    hall = { "[TCP:flags:PA]-drop-| \\/ ": [-400] * 11 }
    assert stred in hall
    for _ in range(0, 2000):
        offspring = evolve.mutation_crossover(logger, population, hall, options)
        assert offspring
        assert str(offspring[0]).strip() != "[TCP:flags:PA]-drop-| \/" # should always reject this mutation
    print("No rejected mutations found.")


def test_driver(logger):
    """
    Tests evolve.py driver.
    """
    cmd = [
        "--no-lock-file",
        "--eval-only", "\/",
        "--test-type", "http",
        "--port", "80",
        "--censor", "censor2",
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
        "--bad-word", "facebook",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    try:
        evolve.driver(cmd)
    finally:
        print("Test shutting down any lingering containers.")
        common.clean_containers()

def test_driver_lock_file(logger):
    """
    Tests driver with lock file
    """
    # Try with lock file
    cmd = [
        "--population", "10",
        "--generations", "1",
        "--test-type", "http",
        "--port", "80",
        "--censor", "censor2",
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
        "--bad-word", "facebook",
        "--force-cleanup",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    try:
        evolve.driver(cmd)
    finally:
        print("Test shutting down any lingering containers.")
        common.clean_containers()


def test_driver_failure_cases(logger):
    """
    Tests driver error handling
    """
    print("Testing --no-eval with --eval-only")
    # Try --no-eval and --eval-only
    cmd = [
        "--population", "10",
        "--generations", "1",
        "--test-type", "http",
        "--no-eval",
        "--eval-only", "\/",
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
    ]
    assert not evolve.driver(cmd)

    print("testing with unparseable seed")
    # Try with unparseable seed
    cmd = [
        "--population", "10",
        "--generations", "1",
        "--test-type", "http",
        "--seed", "<thiswillnotparse>",
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
    ]
    with pytest.raises(actions.tree.ActionTreeParseError):
        evolve.driver(cmd)

    print("testing with nonexistent field")
    # Try with unparseable seed
    cmd = [
        "--population", "10",
        "--generations", "1",
        "--test-type", "http",
        "--seed", "[TCP:thisdontexist:1]-drop-|",
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
    ]
    with pytest.raises(AssertionError):
        evolve.driver(cmd)


def test_argparse():
    """
    Normally we don't test argparsers, but the evolve.py argparser involves collecting
    help strings and importing plugins, so we test it here.
    """
    cmd = ["--help"]
    # Should print multiple help messages and raise SystemExit
    with pytest.raises(SystemExit):
        evolve.get_args(cmd)

    cmd = [
        "--no-lock-file",
        "--population", "10",
        "--generations", "1",
        "--test-type", "http",
        "--port", "80",
        "--censor", "censor2",
        "--log", "debug",
        "--no-skip-empty",
    ]
    args = evolve.get_args(cmd)
    assert args.no_lock_file
    assert args.population == 10
    assert args.test_type == "http"
    assert args.log == "debug"


def test_genetic_solve():
    """
    Normally we don't test argparsers, but the evolve.py argparser involves collecting
    help strings and importing plugins, so we test it here.
    """
    cmd = [
        "--population", "3",
        "--generations", "1",
        "--test-type", "http",
        "--port", "80",
        "--censor", "censor2",
        "--log", "info",
        "--seed", "[TCP:flags:PA]-duplicate-|",
        "--no-skip-empty",
    ]
    print(evolve.driver(cmd))
    print("testing without evaluator")
    cmd = [
        "--no-eval",
        "--no-lock-file",
        "--population", "3",
        "--generations", "1",
        "--test-type", "http",
        "--port", "80",
        "--censor", "censor2",
        "--log", "info",
        "--seed", "[TCP:flags:PA]-duplicate-|",
        "--no-skip-empty",
    ]
    print(evolve.driver(cmd))
