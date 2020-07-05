import logging
import pytest

import actions.tree
import actions.drop
import actions.tamper
import actions.duplicate
import actions.sleep
import actions.utils
import actions.strategy
import evaluator
import evolve
import layers.layer

from scapy.all import IP, TCP, Raw


def test_mate(logger):
    """
    Tests string representation.
    """
    strat1 = actions.utils.parse("\/", logger)
    strat2 = actions.utils.parse("\/", logger)
    assert not actions.strategy.mate(strat1, strat2, 1)

    strat1 = actions.utils.parse("[TCP:flags:R]-duplicate-| \/", logger)
    strat2 = actions.utils.parse("[TCP:flags:S]-drop-| \/", logger)

    # Mate with 100% probability
    actions.strategy.mate(strat1, strat2, 1)
    assert str(strat1).strip() == "[TCP:flags:R]-drop-| \/"
    assert str(strat2).strip() == "[TCP:flags:S]-duplicate-| \/"

    strat1 = actions.utils.parse("[TCP:flags:R]-duplicate(drop,drop)-| \/", logger)
    strat2 = actions.utils.parse("[TCP:flags:S]-drop-| \/", logger)
    assert str(strat1).strip() == "[TCP:flags:R]-duplicate(drop,drop)-| \/"
    assert str(strat2).strip() == "[TCP:flags:S]-drop-| \/"

    # Mate with 100% probability
    actions.strategy.mate(strat1, strat2, 1)
    assert str(strat1).strip() in ["[TCP:flags:R]-duplicate(drop,drop)-| \/",
                           "[TCP:flags:R]-drop-| \/"]
    assert str(strat2).strip() in ["[TCP:flags:S]-duplicate(drop,drop)-| \/",
                           "[TCP:flags:S]-drop-| \/"]

    # Cannot have a strategy with a space in it - malformed
    with pytest.raises(AssertionError):
        actions.utils.parse("[TCP:flags:R]-duplicate(drop, drop)-| \/", logger)


def test_init(logger):
    """
    Tests various strategy initialization.
    """
    # 1 inbound tree with 1 action, zero outbound trees
    strat = actions.strategy.Strategy([], []).initialize(logger, 1, 0, 1, 0, None)
    s = "[TCP:flags:R]-drop-| \/"
    # initialize with a seed
    assert str(actions.strategy.Strategy([], []).initialize(logger, 1, 1, 1, 1, s)).strip() == s


def test_run(logger):
    """
    Tests strategy execution.
    """
    strat1 = actions.utils.parse("[TCP:flags:R]-duplicate-| \/", logger)
    strat2 = actions.utils.parse("[TCP:flags:S]-drop-| \/", logger)
    strat3 = actions.utils.parse("[TCP:flags:A]-duplicate(tamper{TCP:dataofs:replace:0},)-| \/", logger)
    strat4 = actions.utils.parse("[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:15239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:chksum:replace:14539}(tamper{TCP:seq:corrupt},),),))-| \/", logger)

    p1 = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    packets = strat1.act_on_packet(p1, logger, direction="out")
    assert packets, "Strategy dropped SYN packets"
    assert len(packets) == 1
    assert packets[0]["TCP"].flags == "S"

    p1 = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    packets = strat2.act_on_packet(p1, logger, direction="out")
    assert not packets, "Strategy failed to drop SYN packets"

    p1 = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="A", dataofs=5))
    packets = strat3.act_on_packet(p1, logger, direction="out")
    assert packets, "Strategy dropped packets"
    assert len(packets) == 2, "Incorrect number of packets emerged from forest"
    assert packets[0]["TCP"].dataofs == 0, "Packet tamper failed"
    assert packets[1]["TCP"].dataofs == 5, "Duplicate packet was tampered"

    p1 = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="A", dataofs=5, chksum=100))
    packets = strat4.act_on_packet(p1, logger, direction="out")
    assert packets, "Strategy dropped packets"
    assert len(packets) == 3, "Incorrect number of packets emerged from forest"
    assert packets[0]["TCP"].flags == "R", "Packet tamper failed"
    assert packets[0]["TCP"].chksum != p1["TCP"].chksum, "Packet tamper failed"
    assert packets[1]["TCP"].flags == "S", "Packet tamper failed"
    assert packets[1]["TCP"].chksum != p1["TCP"].chksum, "Packet tamper failed"
    assert packets[1]["TCP"].seq != p1["TCP"].seq, "Packet tamper failed"
    assert packets[2]["TCP"].flags == "A", "Duplicate failed"

    strat4 = actions.utils.parse("[TCP:load:]-tamper{TCP:load:replace:mhe76jm0bd}(fragment{ip:-1:True}(tamper{IP:load:corrupt},drop),)-| \/ ", logger)
    p1 = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    packets = strat4.act_on_packet(p1, logger)

    # Will fail with scapy 2.4.2 if packet is reparsed
    strat5 = actions.utils.parse("[TCP:options-eol:]-tamper{TCP:load:replace:o}(tamper{TCP:dataofs:replace:11},)-| \/", logger)
    p1 = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S"))
    packets = strat5.act_on_packet(p1, logger)


def test_mutate():
    """
    Mutates some stratiges
    """
    logger = logging.getLogger("test")
    logger.setLevel(logging.ERROR)
    strat1 = actions.utils.parse("\/", logger)
    strat1.environment_id = 1000
    strat1.mutate(logger)
    assert len(strat1.out_actions) == 1
    assert len(strat1.in_actions) == 1
    assert strat1.out_actions[0].environment_id == 1000
    strat1.out_actions[0].mutate()
    assert strat1.out_actions[0].environment_id == 1000


def test_pretty_print(logger):
    """
    Tests if the string representation of this strategy is correct
    """
    strat = actions.utils.parse("[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \/ ", logger)
    correct = "TCP:flags:A\nduplicate\n├── tamper{TCP:flags:replace:R}\n│   └── tamper{TCP:chksum:corrupt}\n│       └──  ===> \n└──  ===> \n \n \/ \n "
    assert strat.pretty_print() == correct


def test_collection(logger):
    """
    Tests collection phase.
    """
    # Create an evaluator
    cmd = [
        "--test-type", "echo",
        "--censor", "censor2",
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
        "--bad-word", "facebook",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]

    tester = evaluator.Evaluator(cmd, logger)

    canary = evolve.generate_strategy(logger, 0, 0, 0, 0, None)
    environment_id = tester.canary_phase(canary)
    packets = actions.utils.read_packets(environment_id)
    assert packets
    test_pop = []
    for _ in range(0, 5):
        test_pop.append(evolve.generate_strategy(logger, 0, 0, 0, 0, None))
    environment_id = evolve.run_collection_phase(logger, tester)
    packets = actions.utils.read_packets(environment_id)
    assert packets
    assert len(packets) > 1


def test_sleep_parse_handling(logger):
    """
    Tests that the sleep action handles bad parsing.
    """
    print("Testing incorrect parsing:")
    assert not actions.sleep.SleepAction().parse("THISHSOULDFAIL", logger)

    assert actions.sleep.SleepAction().parse("10.5", logger)


def test_get_from_fuzzed_or_real(logger):
    """
    Tests utils.get_from_fuzzed_or_real_packet(environment_id, real_packet_probability):
    """
    # Create an evaluator
    cmd = [
        "--test-type", "echo",
        "--censor", "censor2",
        "--log", actions.utils.CONSOLE_LOG_LEVEL,
        "--no-skip-empty",
        "--bad-word", "facebook",
        "--output-directory", actions.utils.RUN_DIRECTORY
    ]

    tester = evaluator.Evaluator(cmd, logger)

    canary = evolve.generate_strategy(logger, 0, 0, 0, 0, None)
    environment_id = tester.canary_phase(canary)
    for i in range(0, 100):
        proto, field, value = actions.utils.get_from_fuzzed_or_real_packet(environment_id, 1)
        assert proto
        assert field
        assert value is not None
        proto, field, value = actions.utils.get_from_fuzzed_or_real_packet(environment_id, 0)
        assert proto
        assert field
        assert value is not None


def test_fail_cases(logger):
    """
    Odd strategies that have caused failures in nightly testing.
    """
    s = "[IP:proto:6]-tamper{IP:proto:replace:125}(fragment{tcp:48:True:26}(tamper{TCP:options-md5header:replace:37f0e737da65224ea03d46c713ed6fd2},),)-| \/ "
    s = actions.utils.parse(s, logger)

    p = layers.packet.Packet(IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=2222, dport=3333, seq=100, ack=100, flags="S")/Raw("aaaaaaaaaa"))
    s.act_on_packet(p, logger)
