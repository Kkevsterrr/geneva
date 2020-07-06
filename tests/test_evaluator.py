import logging
import os
import pytest
import tempfile

import actions.tree
import actions.drop
import actions.tamper
import actions.duplicate
import actions.utils
import actions.strategy
import evaluator
import evolve
import common

import netifaces
from scapy.all import IP, TCP

from pprint import pprint

@pytest.mark.parametrize("extra_args", [[], ["--no-fitness-file"], ["--workers", "2"]], ids=["with_fitness_file", "no_fitness_file", "two_workers"])
def test_evaluator_http_client(logger, extra_args):
    """
    Tests http plugin client.
    """
    with tempfile.TemporaryDirectory() as output_dir:
        cmd = [
            "--test-type", "http",
            "--port", "80",
            "--external-server",
            "--server", "http://google.com",
            "--no-canary",
            "--log", actions.utils.CONSOLE_LOG_LEVEL,
            "--no-skip-empty",
            "--output-directory", output_dir
        ]
        cmd += extra_args
        tester = evaluator.Evaluator(cmd, logger)
        population = [
            "\/ [UDP:dport:100]-drop-|", # strategy with an unused action tree
            "\/",
            "[TCP:flags:PA]-sleep{1}-|",
            "[TCP:flags:PA]-drop-|" # strategy that will break TCP connection
        ]
        population = [actions.utils.parse(ind, logger) for ind in population]
        inds = tester.evaluate(population)
        assert len(inds) == 4
        assert inds[0].fitness == 389 # -10 for unused, -1 for size
        assert inds[1].fitness == 400
        assert inds[2].fitness == 399 # -1 for size
        assert inds[3].fitness == -480
        for ind in inds:
            assert os.path.exists(os.path.join(output_dir, "logs", ind.environment_id + ".client.log"))
            assert os.path.exists(os.path.join(output_dir, "logs", ind.environment_id + ".engine.log"))
            assert os.path.exists(os.path.join(output_dir, "flags", ind.environment_id + ".fitness"))

@pytest.mark.parametrize("extra_args", [[], ["--use-tcp"]], ids=["udp", "tcp"])
def test_evaluator_dns_client_external_server(logger, extra_args):
    """
    Tests http plugin client.
    """
    with tempfile.TemporaryDirectory() as output_dir:
        cmd = [
            "--test-type", "dns",
            "--external-server",
            "--log", actions.utils.CONSOLE_LOG_LEVEL,
            "--no-skip-empty",
            "--output-directory", output_dir
        ]
        cmd += extra_args
        tester = evaluator.Evaluator(cmd, logger)
        if "--use-tcp" not in cmd:
            population = [
                "\/ [UDP:dport:100]-drop-|", # strategy with an unused action tree
                "\/",
                "[UDP:dport:53]-sleep{1}-|",
                "[UDP:dport:53]-drop-|", # strategy that will break query
                "[UDP:dport:53]-tamper{DNS:qd:compress}-|"
            ]
        else:
            population = [
                "\/ [UDP:dport:100]-drop-|", # strategy with an unused action tree
                "\/",
                "[TCP:flags:PA]-sleep{1}-|",
                "[TCP:flags:PA]-drop-|", # strategy that will break query
                # "[TCP:flags:PA]-tamper{DNS:qd:compress}-|" # Not implemented due to TCP protocol limitations
            ]

        population = [actions.utils.parse(ind, logger) for ind in population]
        inds = tester.evaluate(population)

        # Special case for UDP
        assert len(inds) == 5 if "--use-tcp" not in cmd else 4

        assert inds[0].fitness == 389  # -10 for unused, -1 for size
        assert inds[1].fitness == 400
        assert inds[2].fitness == 399  # -1 for size
        assert inds[3].fitness == -400

        if "--use-tcp" not in cmd:
            assert inds[4].fitness > 0

        for ind in inds:
            assert os.path.exists(os.path.join(output_dir, "logs", ind.environment_id + ".client.log"))
            assert os.path.exists(os.path.join(output_dir, "logs", ind.environment_id + ".engine.log"))
            if ind.fitness > 0:
                assert os.path.exists(os.path.join(output_dir, "flags", ind.environment_id + ".dnsresult"))
            assert os.path.exists(os.path.join(output_dir, "flags", ind.environment_id + ".fitness"))


def test_evaluator_censor_log_on_debug(logger):
    """
    Tests http plugin client.
    """
    print("Test testing a failing strategy and a successful strategies, dumping logs on success and failure.")
    cmd = [
        "--test-type", "http",
        "--port", "80",
        "--censor", "censor2",
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
        "--bad-word", "facebook",
        "--log-on-fail",
        "--log-on-success",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    try:
        tester = evaluator.Evaluator(cmd, logger)
        population = [
            "\/",
            "\/ [TCP:flags:R]-drop-|",
        ]
        population = [actions.utils.parse(ind, logger) for ind in population]
        inds = tester.evaluate(population)
        assert len(inds) == 2

    finally:
        print("Test shutting down any lingering containers.")
        common.clean_containers()


def test_evaluator_censor(logger):
    """
    Tests http plugin client.
    """
    cmd = [
        "--test-type", "http",
        "--port", "80",
        "--censor", "censor2",
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
        "--bad-word", "facebook",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    try:
        tester = evaluator.Evaluator(cmd, logger)
        population = [
            "\/ [UDP:dport:100]-drop-|", # strategy with an unused action tree
            "\/",
            "[TCP:flags:PA]-sleep{1}-|",
            "[TCP:flags:PA]-drop-|" # strategy that will break TCP connection
        ]
        population = [actions.utils.parse(ind, logger) for ind in population]
        inds = tester.evaluate(population)
        assert len(inds) == 4
        assert inds[0].fitness == -370 # -10 for unused
        assert inds[1].fitness == -360
        assert inds[2].fitness == -360
        assert inds[3].fitness == -480
        for ind in inds:
            assert os.path.exists(os.path.join(actions.utils.RUN_DIRECTORY, "logs", ind.environment_id + ".client.log"))
            assert os.path.exists(os.path.join(actions.utils.RUN_DIRECTORY, "logs", ind.environment_id + ".engine.log"))
            assert os.path.exists(os.path.join(actions.utils.RUN_DIRECTORY, "flags", ind.environment_id + ".fitness"))

    finally:
        print("Test shutting down any lingering containers.")
        common.clean_containers()


def test_evaluator_censor_echo_debug(logger):
    """
    Tests evaluator handling of debug mode.
    """
    evaluator_censor_echo_common(logger, "debug")


def test_evaluator_censor_echo(logger):
    """
    Tests echo plugin client.
    """
    evaluator_censor_echo_common(logger, actions.utils.CONSOLE_LOG_LEVEL)


def evaluator_censor_echo_common(logger, log_level):
    """
    Common test for test_evaluator_censor_echo and test_evaluator_censor_echo_debug
    to handle both log levels.
    """
    original_level = actions.utils.CONSOLE_LOG_LEVEL
    logger.setLevel(log_level.upper())
    cmd = [
        "--test-type", "echo",
        "--censor", "censor2",
        "--log", log_level,
        "--no-skip-empty",
        "--bad-word", "facebook",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    try:
        tester = evaluator.Evaluator(cmd, logger)
        population = [
            "\/ [UDP:dport:100]-drop-|", # strategy with an unused action tree
            "\/",
            "[TCP:flags:PA]-sleep{1}-|",
            "[TCP:flags:PA]-drop-|" # strategy that will break TCP connection
        ]
        population = [actions.utils.parse(ind, logger) for ind in population]
        inds = tester.evaluate(population)
        assert len(inds) == 4
        assert inds[0].fitness == -370 # -10 for unused
        assert inds[1].fitness == -360
        assert inds[2].fitness == -360
        assert inds[3].fitness == -400
        for ind in inds:
            assert os.path.exists(os.path.join(actions.utils.RUN_DIRECTORY, "logs", ind.environment_id + ".client.log"))
            assert os.path.exists(os.path.join(actions.utils.RUN_DIRECTORY, "logs", ind.environment_id + ".engine.log"))
            assert os.path.exists(os.path.join(actions.utils.RUN_DIRECTORY, "flags", ind.environment_id + ".fitness"))

    finally:
        logger.setLevel(original_level.upper())
        print("Test shutting down any lingering containers.")
        common.clean_containers()


def test_evaluator_censor_discard_debug(logger):
    """
    Tests evaluator's handling of debug mode
    """
    test_evaluator_censor_discard(logger, "debug")


def test_evaluator_censor_discard(logger, log_level="info"):
     """
     Tests discard plugin client for basic functionality. Discard is not
     used regularly.
     """
     logger.setLevel(log_level.upper())
     cmd = [
         "--test-type", "discard",
         "--censor", "censor2",
         "--log", actions.utils.CONSOLE_LOG_LEVEL,
         "--no-skip-empty",
         "--bad-word", "facebook",
         "--output-directory", actions.utils.RUN_DIRECTORY
     ]
     try:
         tester = evaluator.Evaluator(cmd, logger)
         population = [
             "\/ [TCP:flags:R]-drop-|", # strategy that will beat censor
             "\/ [UDP:dport:100]-drop-|", # strategy with an unused action tree
             "\/",
             # This is not tested, as we know it will not pass. See plugins/discard/client.py for an explanation
             #"[TCP:flags:PA]-drop-| [TCP:flags:FPA]-drop-|" # strategy that will break TCP connection
         ]
         population = [actions.utils.parse(ind, logger) for ind in population]
         inds = tester.evaluate(population)
         assert len(inds) == 3
         assert inds[0].fitness > 0
         assert inds[1].fitness == -410  # -10 for unused
         assert inds[2].fitness == -400
         for ind in inds:
             assert os.path.exists(os.path.join(actions.utils.RUN_DIRECTORY, "logs", ind.environment_id + ".client.log"))
             assert os.path.exists(os.path.join(actions.utils.RUN_DIRECTORY, "logs", ind.environment_id + ".engine.log"))
             assert os.path.exists(os.path.join(actions.utils.RUN_DIRECTORY, "flags", ind.environment_id + ".fitness"))

     finally:
         print("Test shutting down any lingering containers.")
         os.system("docker stop server_main; docker stop censor_main; docker stop client_main")


def test_evaluator_censor_workers(logger):
    """
    Tests http plugin client.
    """
    cmd = [
        "--test-type", "http",
        "--port", "80",
        "--censor", "censor2",
        "--workers", "2",
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
        "--bad-word", "facebook",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    try:
        tester = evaluator.Evaluator(cmd, logger)
        population = [
            "\/ [UDP:dport:100]-drop-|", # strategy with an unused action tree
            "\/",
            "[TCP:flags:PA]-sleep{1}-|",
            "[TCP:flags:PA]-drop-|", # strategy that will break TCP connection
            "\/ [TCP:flags:R]-drop-|"
        ]
        population = [actions.utils.parse(ind, logger) for ind in population]
        inds = tester.evaluate(population)
        assert len(inds) == 5
        assert inds[0].fitness == -370 # -10 for unused
        assert inds[1].fitness == -360
        assert inds[2].fitness == -360
        assert inds[3].fitness == -480
        assert inds[4].fitness == 399
        for ind in inds:
            assert os.path.exists(os.path.join(actions.utils.RUN_DIRECTORY, "logs", ind.environment_id + ".client.log"))
            assert os.path.exists(os.path.join(actions.utils.RUN_DIRECTORY, "logs", ind.environment_id + ".engine.log"))
            assert os.path.exists(os.path.join(actions.utils.RUN_DIRECTORY, "flags", ind.environment_id + ".fitness"))

    finally:
        print("Test shutting down any lingering containers.")
        os.system("docker stop server_0; docker stop censor_0; docker stop client_0")
        os.system("docker stop server_1; docker stop censor_1; docker stop client_1")


def test_evaluator_http_client_skip_empty(logger):
    """
    Tests http plugin client.
    """
    with tempfile.TemporaryDirectory() as output_dir:
        cmd = [
            "--test-type", "http",
            "--port", "80",
            "--external-server",
            "--server", "http://google.com",
            "--no-canary",
            "--log", actions.utils.CONSOLE_LOG_LEVEL,
            "--output-directory", output_dir
        ]
        tester = evaluator.Evaluator(cmd, logger)
        population = [
            "\/ [UDP:dport:100]-drop-|", # strategy with an unused action tree
            "\/",
            "[TCP:flags:PA]-sleep{1}-|",
            "[TCP:flags:PA]-drop-|" # strategy that will break TCP connection
        ]
        population = [actions.utils.parse(ind, logger) for ind in population]
        inds = tester.evaluate(population)
        assert len(inds) == 4
        assert inds[0].fitness == 389 # -10 for unused, -1 for size
        assert inds[1].fitness == -1000 # empty - skipped
        assert inds[2].fitness == 399 # -1 for size
        assert inds[3].fitness == -480
        for ind in inds:
            if ind.fitness == -1000:
                continue
            assert os.path.exists(os.path.join(output_dir, "logs", ind.environment_id + ".client.log"))
            assert os.path.exists(os.path.join(output_dir, "logs", ind.environment_id + ".engine.log"))
            assert os.path.exists(os.path.join(output_dir, "flags", ind.environment_id + ".fitness"))


def test_evaluator_http_client_injected_http(logger):
    """
    Tests http plugin client.
    """
    with tempfile.TemporaryDirectory() as output_dir:
        cmd = [
            "--test-type", "http",
            "--port", "80",
            "--external-server",
            "--injected-http-contains", "google",
            "--server", "http://google.com",
            "--no-canary",
            "--log", actions.utils.CONSOLE_LOG_LEVEL,
            "--no-skip-empty",
            "--output-directory", output_dir
        ]
        tester = evaluator.Evaluator(cmd, logger)
        population = [
            "\/ [UDP:dport:100]-drop-|", # strategy with an unused action tree
            "\/",
            "[TCP:flags:PA]-drop-|" # strategy that will break TCP connection
        ]
        population = [actions.utils.parse(ind, logger) for ind in population]
        inds = tester.evaluate(population)
        assert len(inds) == 3
        assert inds[0].fitness == -370 # -10 for unused action, -360 for failing
        assert inds[1].fitness == -360
        assert inds[2].fitness == -480
        for ind in inds:
            assert os.path.exists(os.path.join(output_dir, "logs", ind.environment_id + ".client.log"))
            assert os.path.exists(os.path.join(output_dir, "logs", ind.environment_id + ".engine.log"))
            assert os.path.exists(os.path.join(output_dir, "flags", ind.environment_id + ".fitness"))


# Many sites inside the external pool do not let multiple requests from travis,
# making the test frequently have false negative failures.
@pytest.mark.skip()
def test_evaluator_http_client_external_sites(logger):
    """
    Tests http plugin client.
    """
    with tempfile.TemporaryDirectory() as output_dir:
        cmd = [
            "--test-type", "http",
            "--external-server",
            "--use-external-sites",
            "--no-canary",
            "--log", actions.utils.CONSOLE_LOG_LEVEL,
            "--no-skip-empty",
            "--output-directory", output_dir
        ]
        tester = evaluator.Evaluator(cmd, logger)
        population = [
            "\/ [UDP:dport:100]-drop-|", # strategy with an unused action tree
            "\/",
            "[TCP:flags:PA]-drop-|" # strategy that will break TCP connection
        ]
        population = [actions.utils.parse(ind, logger) for ind in population]
        inds = tester.evaluate(population)
        assert len(inds) == 3
        assert inds[0].fitness == 389 # -10 for unused, -1 for size
        assert inds[1].fitness == 400
        assert inds[2].fitness == -480
        for ind in inds:
            assert os.path.exists(os.path.join(output_dir, "logs", ind.environment_id + ".client.log"))
            assert os.path.exists(os.path.join(output_dir, "logs", ind.environment_id + ".engine.log"))
            assert os.path.exists(os.path.join(output_dir, "flags", ind.environment_id + ".fitness"))


def test_evaluator_external_client_external_sites(client_worker, logger):
    """
    Tests evaluator server side with external client with --use-external-sites.
    """
    population = [
        "\/",
    ]

    population = [actions.utils.parse(ind, logger) for ind in population]
    cmd = [
        "--test-type", "http",
        "--external-server",
        "--external-client", client_worker["worker"],
        "--use-external-sites",
        "--no-canary",
        "--log-on-fail", # this test should not fail, so log if it does
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    tester = evaluator.Evaluator(cmd, logger)

    inds = tester.evaluate(population)
    assert len(inds) == 1
    assert str(inds[0]).strip() == "\/"
    assert inds[0].fitness == 400


def test_evaluator_external_dns_client(client_worker, logger):
    """
    Tests evaluator server side with external client with --use-external-sites.
    """
    population = [
        "\/",
    ]

    population = [actions.utils.parse(ind, logger) for ind in population]
    cmd = [
        "--test-type", "dns",
        "--external-server",
        "--external-client", client_worker["worker"],
        "--log-on-fail", # this test should not fail, so log if it does
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    tester = evaluator.Evaluator(cmd, logger)

    inds = tester.evaluate(population)
    assert len(inds) == 1
    assert str(inds[0]).strip() == "\/"


@pytest.mark.parametrize("args", [["--test-type", "http", "--port", "80"], ["--test-type", "dns", "--port", "53"]], ids=["http", "dns"])
def test_evaluator_external_client_server_side(client_worker, logger, args):
    """
    Tests evaluator server side with external client.
    """
    if "http" in args or "--use-tcp" in args:
        population = [
            "\/ [UDP:dport:100]-drop-|", # strategy with an unused action tree
            "\/",
            "[TCP:flags:SA]-drop-|" # strategy that will break TCP connection
        ]
    else:
        population = [
            "\/ [UDP:dport:100]-drop-|", # strategy with an unused action tree
            "\/",
            "\/ [UDP:dport:53]-drop-|" # strategy that will break query
        ]

    population = [actions.utils.parse(ind, logger) for ind in population]
    cmd = [
        "--test-type", "http",
        "--external-client", client_worker["worker"],
        "--server-side",
        "--public-ip", get_ip(),
        "--timeout", "15",
        "--no-canary",
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    cmd += args
    tester = evaluator.Evaluator(cmd, logger)

    inds = tester.evaluate(population)
    assert len(inds) == 3
    assert inds[0].fitness == 389
    assert inds[1].fitness == 400
    assert inds[2].fitness < 0

    # Request a server side without specifying the public ip - should raise an exception
    cmd = [
        "--test-type", "http",
        "--port", "80",
        "--external-client", client_worker["worker"],
        "--server-side",
        "--no-canary",
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    with pytest.raises(AssertionError):
        tester = evaluator.Evaluator(cmd, logger)


def test_evaluator_external_client(client_worker, logger):
    """
    Tests evaluator server side with external client.
    """
    population = [
        "\/",
    ]
    print(client_worker["worker"])
    population = [actions.utils.parse(ind, logger) for ind in population]
    cmd = [
        "--test-type", "http",
        "--port", "80",
        "--external-server",
        "--external-client", client_worker["worker"],
        "--server", "http://google.com",
        "--log-on-fail", # this test should not fail, so log when it does
        "--no-canary",
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    tester = evaluator.Evaluator(cmd, logger)

    inds = tester.evaluate(population)
    assert len(inds) == 1
    assert str(inds[0]).strip() == "\/"
    assert inds[0].fitness == 400


def get_ip():
    """
    Helper method to get the IP address of this host.
    """
    ifaces = netifaces.interfaces()
    for iface in ifaces:
        if "lo" in iface:
            continue
        info = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in info:
            ip = info[netifaces.AF_INET][0]['addr']
            return ip


def test_evaluator_external_client_local_server(client_worker, logger):
    """
    Tests evaluator server side with external client to a locally hosted server.
    """
    population = [
        "\/",
    ]

    population = [actions.utils.parse(ind, logger) for ind in population]
    cmd = [
        "--test-type", "http",
        "--external-client", client_worker["worker"],
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
        "--public-ip", get_ip(),
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    tester = evaluator.Evaluator(cmd, logger)

    inds = tester.evaluate(population)
    assert len(inds) == 1
    assert str(inds[0]).strip() == "\/"
    assert inds[0].fitness == 400



@pytest.mark.skip()
def test_evaluator_get_ip(logger):
    """
    Tests evaluator skip_empty flag.
    """
    # Create an evaluator
    tester = evaluator.Evaluator(logger,                  # logger for the session
                                 "censor2",               # internal censor
                                 None,                    # no external server
                                 actions.utils.RUN_DIRECTORY, # directory to log
                                 workers=4,               # workers to use
                                 runs=1,                  # only need 1 run
                                 test_type="echo",        # use echo test
                                 skip_empty=True)         # skip empty strats
    ip = tester.get_ip()
    tester.public_ip = "1.1.1.1"
    assert tester.get_ip() == "1.1.1.1"


@pytest.mark.skip()
def test_evaluator_external_server(logger):
    """
    Tests evaluator skip_empty flag.
    """
    tester = evaluator.Evaluator(logger,                  # logger for the session
                                 None,                    # no internal censor
                                 "http://facebook.com",   # try to talk to facebook
                                 actions.utils.RUN_DIRECTORY, # directory to log
                                 workers=1,               # workers to use
                                 runs=1,                  # only need 1 run
                                 test_type="http",        # use http test
                                 skip_empty=False)        # don't skip empty strats

    population = [
        "\/",
    ]
    population = [actions.utils.parse(ind, logger) for ind in population]

    inds = tester.evaluate(population)
    assert inds[0].fitness == 400

    tester = evaluator.Evaluator(logger,                  # logger for the session
                                 None,                    # no internal censor
                                 "http://facebook.com",   # try to talk to facebook
                                 actions.utils.RUN_DIRECTORY, # directory to log
                                 workers=1,               # workers to use
                                 runs=1,                  # only need 1 run
                                 test_type="http",        # use http test
                                 skip_empty=True)        # don't skip empty strats

    population = [
        "\/",
    ]
    population = [actions.utils.parse(ind, logger) for ind in population]

    inds = tester.evaluate(population)
    assert inds[0].fitness == -1000

    tester = evaluator.Evaluator(logger,                  # logger for the session
                                 None,                    # no internal censor
                                 None,                    # no external server
                                 actions.utils.RUN_DIRECTORY, # directory to log
                                 use_external_sites=True,
                                 workers=1,               # workers to use
                                 runs=1,                  # only need 1 run
                                 test_type="http",        # use http test
                                 skip_empty=False)        # don't skip empty strats

    population = [
        "\/",
    ]
    population = [actions.utils.parse(ind, logger) for ind in population]

    inds = tester.evaluate(population)
    assert inds[0].fitness == 400


@pytest.mark.skip()
def test_evaluator_skip_empty(logger):
    """
    Tests evaluator skip_empty flag.
    """
    population = [
        "\/",
    ]
    population = [actions.utils.parse(ind, logger) for ind in population]
    # Create an evaluator
    tester = evaluator.Evaluator(logger,                  # logger for the session
                                 "censor2",               # internal censor
                                 None,                    # no external server
                                 actions.utils.RUN_DIRECTORY, # directory to log
                                 workers=4,               # workers to use
                                 runs=1,                  # only need 1 run
                                 test_type="echo",        # use echo test
                                 skip_empty=True)         # skip empty strats
    inds = tester.evaluate(population)
    assert len(inds) == 1
    assert str(inds[0]).strip() == "\/"
    assert inds[0].fitness == -1000

    tester.skip_empty = False
    inds = tester.evaluate(population)
    assert len(inds) == 1
    assert str(inds[0]).strip() == "\/"
    assert inds[0].fitness == -40


@pytest.mark.skip()
@pytest.mark.parametrize("test_type", ["echo", "http"])
def test_evaluator_server_side(logger, test_type):
    """
    Tests evaluator server side flag.
    """
    population = [
        "\/ [TCP:flags:R]-drop-|",
    ]
    population = [actions.utils.parse(ind, logger) for ind in population]
    # Create an evaluator with a server that only sends RSTs to the client
    tester = evaluator.Evaluator(logger,                  # logger for the session
                                 "censor2",               # internal censor
                                 None,                    # no external server
                                 actions.utils.RUN_DIRECTORY, # directory to log
                                 workers=4,               # workers to use
                                 runs=1,                  # only need 1 run for testing
                                 test_type=test_type,     # test both test types
                                 skip_empty=True)         # skip empty strats

    inds = tester.evaluate(population)
    assert len(inds) == 1
    assert str(inds[0]).strip() == "\/ [TCP:flags:R]-drop-|"
    assert inds[0].fitness > 0

    # Switch testing to deploying the Geneva engine on the server side
    tester.server_side = True

    # No RSTs are sent to the sever, so this should fail
    inds = tester.evaluate(population)
    assert len(inds) == 1
    assert str(inds[0]).strip() == "\/ [TCP:flags:R]-drop-|"
    assert inds[0].fitness < 0

    # Switch the censor to one that sends RSTs to only the server
    tester.censor = "censor5"

    inds = tester.evaluate(population)
    assert len(inds) == 1
    assert str(inds[0]).strip() == "\/ [TCP:flags:R]-drop-|"
    assert inds[0].fitness > 0

    tester.test_type = "http"


@pytest.mark.skip()
@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_evaluator_client_dns_test(client_worker, protocol, logger):
    """
    Tests DNS evaluation with external client.
    """
    # Setup the population and test type
    test_type = "dns_tcp"
    if protocol == "udp":
        test_type = "dns"

    population = [
        "\/"
    ]

    population = [actions.utils.parse(ind, logger) for ind in population]
    tester = evaluator.Evaluator(logger,                  # logger for the session
                                 None,                    # no internal censor
                                 None,                    # no external server
                                 actions.utils.RUN_DIRECTORY, # directory to log
                                 workers=1,               # workers to use
                                 runs=1,                  # only need 1 run for testing
                                 external_client=False,   # testing an external client
                                 test_type=test_type,
                                 skip_empty=False)        # don't skip empty strats

    inds = tester.evaluate(population)
    assert len(inds) == 1
    assert str(inds[0]).strip() == "\/"
    assert inds[0].fitness > 0


def test_evaluator_worker_ip_lookup(logger):
    """
    Tests worker IP lookup by specifying a worker name instead of a public IP
    """
    cmd = [
        "--test-type", "http",
        "--public-ip", "example",
        "--external-client", "example",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    test_evaluator = evaluator.Evaluator(cmd, logger)
    assert test_evaluator.public_ip == "0.0.0.0"

    cmd = [
        "--test-type", "http",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    test_evaluator = evaluator.Evaluator(cmd, logger)
    assert not test_evaluator.get_ip()


def test_evaluator_read_fitness(logger):
    """
    tests evaluator read_fitness
    """
    ind = actions.utils.parse("\/", logger)
    ind.environment_id = "test"
    cmd = [
        "--test-type", "http",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    test_evaluator = evaluator.Evaluator(cmd, logger)
    test_evaluator.read_fitness(ind)
    assert ind.fitness == -1000


def test_evaluator_init_nat(logger):
    """
    Sets up evaluator with NAT
    """
    cmd = [
        "--test-type", "http",
        "--sender-ip", "1.1.1.1",
        "--forward-ip", "2.2.2.2",
        "--routing-ip", "3.3.3.3",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]
    test_evaluator = evaluator.Evaluator(cmd, logger)
    assert not test_evaluator.forwarder, "Evaluator set up a forwarder without --act-as-middlebox"
    cmd += ["--act-as-middlebox"]

    test_evaluator = evaluator.Evaluator(cmd, logger)

    assert test_evaluator.forwarder
    assert test_evaluator.forwarder["sender_ip"] == "1.1.1.1"
    assert test_evaluator.forwarder["forward_ip"] == "2.2.2.2"
    assert test_evaluator.forwarder["routing_ip"] == "3.3.3.3"
