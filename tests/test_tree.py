import logging
import os

from scapy.all import IP, TCP
import actions.tree
import actions.drop
import actions.tamper
import actions.duplicate
import actions.utils
import layers.packet


def test_init():
    """
    Tests initialization
    """
    print(actions.action.Action.get_actions("out"))


def test_count_leaves():
    """
    Tests leaf count is correct.
    """
    a = actions.tree.ActionTree("out")
    logger = logging.getLogger("test")

    assert not a.parse("TCP:reserved:0tamper{TCP:flags:replace:S}-|", logger), "Tree parsed malformed DNA"
    a.parse("[TCP:reserved:0]-tamper{TCP:flags:replace:S}-|", logger)
    duplicate = actions.duplicate.DuplicateAction()
    duplicate2 = actions.duplicate.DuplicateAction()
    drop = actions.drop.DropAction()

    assert a.count_leaves() == 1
    assert a.remove_one()
    a.add_action(duplicate)
    assert a.count_leaves() == 1
    duplicate.left = duplicate2
    assert a.count_leaves() == 1
    duplicate.right = drop
    assert a.count_leaves() == 2


def test_check():
    """
    Tests action tree check function.
    """
    a = actions.tree.ActionTree("out")
    logger = logging.getLogger("test")
    a.parse("[TCP:flags:RA]-tamper{TCP:flags:replace:S}-|", logger)
    p = layers.packet.Packet(IP()/TCP(flags="A"))
    assert not a.check(p, logger)
    p = layers.packet.Packet(IP(ttl=64)/TCP(flags="RA"))
    assert a.check(p, logger)
    assert a.remove_one()
    assert a.check(p, logger)
    a.parse("[TCP:reserved:0]-tamper{TCP:flags:replace:S}-|", logger)
    assert a.check(p, logger)
    a.parse("[IP:ttl:64]-tamper{TCP:flags:replace:S}-|", logger)
    assert a.check(p, logger)
    p = layers.packet.Packet(IP(ttl=15)/TCP(flags="RA"))
    assert not a.check(p, logger)


def test_scapy():
    """
    Tests misc. scapy aspects relevant to strategies.
    """
    a = actions.tree.ActionTree("out")
    logger = logging.getLogger("test")
    a.parse("[TCP:reserved:0]-tamper{TCP:flags:replace:S}-|", logger)
    p = layers.packet.Packet(IP()/TCP(flags="A"))
    assert a.check(p, logger)
    packets = a.run(p, logger)
    assert packets[0][TCP].flags == "S"
    p = layers.packet.Packet(IP()/TCP(flags="A"))
    assert a.check(p, logger)
    a.parse("[TCP:reserved:0]-tamper{TCP:chksum:corrupt}-|", logger)
    packets = a.run(p, logger)
    assert packets[0][TCP].chksum
    assert a.check(p, logger)


def test_str():
    """
    Tests string representation.
    """
    logger = logging.getLogger("test")

    t = actions.trigger.Trigger("field", "flags", "TCP")
    a = actions.tree.ActionTree("out", trigger=t)
    assert str(a).strip() == "[%s]-|" % str(t)
    tamper = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="S")
    tamper2 = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="R")
    assert a.add_action(tamper)
    assert str(a).strip() == "[TCP:flags:0]-tamper{TCP:flags:replace:S}-|"
    # Tree will not add a duplicate action
    assert not a.add_action(tamper)
    assert str(a).strip() == "[TCP:flags:0]-tamper{TCP:flags:replace:S}-|"
    assert a.add_action(tamper2)
    assert str(a).strip() == "[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R},)-|"
    assert a.add_action(actions.duplicate.DuplicateAction())
    assert str(a).strip() == "[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R}(duplicate,),)-|"
    drop = actions.drop.DropAction()
    assert a.add_action(drop)
    assert str(a).strip() == "[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R}(duplicate(drop,),),)-|" or \
           str(a).strip() == "[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R}(duplicate(,drop),),)-|"
    assert a.remove_action(drop)
    assert str(a).strip() == "[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R}(duplicate,),)-|"
    # Cannot remove action that is not present
    assert not a.remove_action(drop)
    assert str(a).strip() == "[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R}(duplicate,),)-|"

    a = actions.tree.ActionTree("out", trigger=t)
    orig = "[TCP:urgptr:15963]-duplicate(,drop)-|"
    a.parse(orig, logger)
    assert a.remove_one()
    assert orig != str(a)
    assert str(a) in ["[TCP:urgptr:15963]-drop-|", "[TCP:urgptr:15963]-duplicate-|"]


def test_pretty_print_send():
    t = actions.trigger.Trigger("field", "flags", "TCP")
    a = actions.tree.ActionTree("out", trigger=t)
    duplicate = actions.duplicate.DuplicateAction()
    a.add_action(duplicate)
    correct_string = "TCP:flags:0\nduplicate\n├──  ===> \n└──  ===> "
    assert a.pretty_print() == correct_string


def test_pretty_print(logger):
    """
    Print complex tree, although difficult to test
    """
    t = actions.trigger.Trigger("field", "flags", "TCP")
    a = actions.tree.ActionTree("out", trigger=t)
    tamper = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="S")
    tamper2 = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="R")
    duplicate = actions.duplicate.DuplicateAction()
    duplicate2 = actions.duplicate.DuplicateAction()
    duplicate3 = actions.duplicate.DuplicateAction()
    duplicate4 = actions.duplicate.DuplicateAction()
    duplicate5 = actions.duplicate.DuplicateAction()
    drop = actions.drop.DropAction()
    drop2 = actions.drop.DropAction()
    drop3 = actions.drop.DropAction()
    drop4 = actions.drop.DropAction()

    duplicate.left = duplicate2
    duplicate.right = duplicate3
    duplicate2.left = tamper
    duplicate2.right = drop
    duplicate3.left = duplicate4
    duplicate3.right = drop2
    duplicate4.left = duplicate5
    duplicate4.right = drop3
    duplicate5.left = drop4
    duplicate5.right = tamper2

    a.add_action(duplicate)
    correct_string = "TCP:flags:0\nduplicate\n├── duplicate\n│   ├── tamper{TCP:flags:replace:S}\n│   │   └──  ===> \n│   └── drop\n└── duplicate\n    ├── duplicate\n    │   ├── duplicate\n    │   │   ├── drop\n    │   │   └── tamper{TCP:flags:replace:R}\n    │   │       └──  ===> \n    │   └── drop\n    └── drop"
    assert a.pretty_print() == correct_string
    assert a.pretty_print(visual=True)
    assert os.path.exists("tree.png")
    os.remove("tree.png")
    a.parse("[TCP:flags:0]-|", logger)
    a.pretty_print(visual=True) # Empty action tree
    assert not os.path.exists("tree.png")

def test_pretty_print_order():
    """
    Tests the left/right ordering by reading in a new tree
    """
    logger = logging.getLogger("test")
    a = actions.tree.ActionTree("out")
    assert a.parse("[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:14239},),duplicate(tamper{TCP:flags:replace:S}(tamper{TCP:chksum:replace:14239},),))-|", logger)
    correct_pretty_print = "TCP:flags:A\nduplicate\n├── tamper{TCP:flags:replace:R}\n│   └── tamper{TCP:chksum:replace:14239}\n│       └──  ===> \n└── duplicate\n    ├── tamper{TCP:flags:replace:S}\n    │   └── tamper{TCP:chksum:replace:14239}\n    │       └──  ===> \n    └──  ===> "
    assert a.pretty_print() == correct_pretty_print

def test_parse():
    """
    Tests string parsing.
    """
    logger = logging.getLogger("test")
    t = actions.trigger.Trigger("field", "flags", "TCP")
    a = actions.tree.ActionTree("out", trigger=t)

    base_t = actions.trigger.Trigger("field", "flags", "TCP")
    base_a = actions.tree.ActionTree("out", trigger=base_t)
    tamper = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="S")
    tamper2 = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="R")
    tamper3 = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="S")
    tamper4 = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="R")
    a.parse("[TCP:flags:0]-|", logger)
    assert str(a) == str(base_a)
    assert len(a) == 0

    base_a.add_action(tamper)

    assert a.parse("[TCP:flags:0]-tamper{TCP:flags:replace:S}-|", logger)

    assert str(a) == str(base_a)
    assert len(a) == 1
    assert a.parse("[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R},)-|", logging.getLogger("test"))
    base_a.add_action(tamper2)
    assert str(a) == str(base_a)
    assert len(a) == 2

    base_a.add_action(tamper3)
    base_a.add_action(tamper4)
    assert a.parse("[TCP:flags:0]-tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R}(tamper{TCP:flags:replace:S}(tamper{TCP:flags:replace:R},),),)-|", logging.getLogger("test"))
    assert str(a) == str(base_a)
    assert len(a) == 4

    base_t = actions.trigger.Trigger("field", "flags", "TCP")
    base_a = actions.tree.ActionTree("out", trigger=base_t)
    duplicate = actions.duplicate.DuplicateAction()
    assert a.parse("[TCP:flags:0]-duplicate-|", logger)
    base_a.add_action(duplicate)
    assert str(a) == str(base_a)
    tamper = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="S")
    tamper2 = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="R")
    tamper3 = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="A")
    tamper4 = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="R")
    duplicate.left = tamper
    assert a.parse("[TCP:flags:0]-duplicate(tamper{TCP:flags:replace:S},)-|", logger)
    assert str(a) == str(base_a)

    duplicate.right = tamper2
    assert a.parse("[TCP:flags:0]-duplicate(tamper{TCP:flags:replace:S},tamper{TCP:flags:replace:R})-|", logger)
    assert str(a) == str(base_a)

    tamper2.left = tamper3
    assert a.parse("[TCP:flags:0]-duplicate(tamper{TCP:flags:replace:S},tamper{TCP:flags:replace:R}(tamper{TCP:flags:replace:A},))-|", logger)
    assert str(a) == str(base_a)

    strategy = actions.utils.parse("[TCP:flags:0]-duplicate(tamper{TCP:flags:replace:S},tamper{TCP:flags:replace:R})-| \/", logger)
    assert strategy
    assert len(strategy.out_actions[0]) == 3
    assert len(strategy.in_actions) == 0

    assert not a.parse("[]", logger) # No valid trigger
    assert not a.parse("[TCP:flags:0]-", logger) # No valid ending "|"
    assert not a.parse("[TCP:]-|", logger) # invalid trigger
    assert not a.parse("[TCP:flags:0]-foo-|", logger) # Non-existent action
    assert not a.parse("[TCP:flags:0]--|", logger) # Empty action
    assert not a.parse("[TCP:flags:0]-duplicate(,,,)-|", logger) # Bad tree
    assert not a.parse("[TCP:flags:0]-duplicate()))-|", logger) # Bad tree
    assert not a.parse("[TCP:flags:0]-duplicate(((()-|", logger) # Bad tree
    assert not a.parse("[TCP:flags:0]-duplicate(,))))-|", logger) # Bad tree
    assert not a.parse("[TCP:flags:0]-drop(duplicate,)-|", logger) # Terminal action with children
    assert not a.parse("[TCP:flags:0]-drop(duplicate,duplicate)-|", logger) # Terminal action with children
    assert not a.parse("[TCP:flags:0]-tamper{TCP:flags:replace:S}(,duplicate)-|", logger) # Non-branching action with right child
    assert not a.parse("[TCP:flags:0]-tamper{TCP:flags:replace:S}(drop,duplicate)-|", logger) # Non-branching action with children


def test_tree():
    """
    Tests basic tree functionality.
    """
    t = actions.trigger.Trigger(None, None, None)
    a = actions.tree.ActionTree("out", trigger=t)
    tamper = actions.tamper.TamperAction()
    tamper2 = actions.tamper.TamperAction()
    duplicate = actions.duplicate.DuplicateAction()

    a.add_action(None)
    a.add_action(tamper)
    assert a.get_slots() == 1
    a.add_action(tamper2)
    assert a.get_slots() == 1
    a.add_action(duplicate)
    assert a.get_slots() == 2

    t = actions.trigger.Trigger(None, None, None)
    a = actions.tree.ActionTree("out", trigger=t)
    drop = actions.drop.DropAction()
    a.add_action(drop)
    assert a.get_slots() == 0
    add_success = a.add_action(tamper)
    assert not add_success
    assert a.get_slots() == 0

    rep = ""
    for s in a.string_repr(a.action_root):
        rep += s
    assert rep == "drop"

    print(str(a))

    assert a.parse("[TCP:flags:A]-duplicate(tamper{TCP:seq:corrupt},)-|", logging.getLogger("test"))
    for act in a:
        print(str(a))
    assert len(a) == 2
    assert a.get_slots() == 2
    for _ in range(100):
        assert str(a.get_rand_action("out", request="DropAction")) == "drop"


def test_remove():
    """
    Tests remove
    """
    t = actions.trigger.Trigger(None, None, None)
    a = actions.tree.ActionTree("out", trigger=t)
    tamper = actions.tamper.TamperAction()
    tamper2 = actions.tamper.TamperAction()
    tamper3 = actions.tamper.TamperAction()
    assert not a.remove_action(tamper)
    a.add_action(tamper)
    assert a.remove_action(tamper)
    a.add_action(tamper)
    a.add_action(tamper2)
    a.add_action(tamper3)
    assert a.remove_action(tamper2)
    assert tamper2 not in a
    assert tamper.left == tamper3
    assert not tamper.right
    assert len(a) == 2
    a = actions.tree.ActionTree("out", trigger=t)
    duplicate = actions.duplicate.DuplicateAction()
    tamper = actions.tamper.TamperAction()
    tamper2 = actions.tamper.TamperAction()
    tamper3 = actions.tamper.TamperAction()
    a.add_action(tamper)
    assert a.action_root == tamper
    duplicate.left = tamper2
    duplicate.right = tamper3
    a.add_action(duplicate)
    assert len(a) == 4
    assert a.remove_action(duplicate)
    assert duplicate not in a
    assert tamper.left == tamper2
    assert not tamper.right
    assert len(a) == 2

    a.parse("[TCP:flags:A]-|", logging.getLogger("test"))
    assert not a.remove_one(), "Cannot remove one with no action root"


def test_len():
    """
    Tests length calculation.
    """
    t = actions.trigger.Trigger(None, None, None)
    a = actions.tree.ActionTree("out", trigger=t)
    tamper = actions.tamper.TamperAction()
    tamper2 = actions.tamper.TamperAction()
    assert len(a) == 0, "__len__ returned wrong length"
    a.add_action(tamper)
    assert len(a) == 1, "__len__ returned wrong length"
    a.add_action(tamper)
    assert len(a) == 1, "__len__ returned wrong length"
    a.add_action(tamper2)
    assert len(a) == 2, "__len__ returned wrong length"
    duplicate = actions.duplicate.DuplicateAction()
    a.add_action(duplicate)
    assert len(a) == 3, "__len__ returned wrong length"


def test_contains():
    """
    Tests contains method
    """
    t = actions.trigger.Trigger(None, None, None)
    a = actions.tree.ActionTree("out", trigger=t)
    tamper = actions.tamper.TamperAction()
    tamper2 = actions.tamper.TamperAction()
    tamper3 = actions.tamper.TamperAction()

    assert not a.contains(tamper), "contains incorrect behavior"
    assert not a.contains(tamper2), "contains incorrect behavior"
    a.add_action(tamper)
    assert a.contains(tamper), "contains incorrect behavior"
    assert not a.contains(tamper2), "contains incorrect behavior"
    add_success = a.add_action(tamper)
    assert not add_success, "added duplicate action"
    assert a.contains(tamper), "contains incorrect behavior"
    assert not a.contains(tamper2), "contains incorrect behavior"
    a.add_action(tamper2)
    assert a.contains(tamper), "contains incorrect behavior"
    assert a.contains(tamper2), "contains incorrect behavior"
    a.remove_action(tamper2)
    assert a.contains(tamper), "contains incorrect behavior"
    assert not a.contains(tamper2), "contains incorrect behavior"
    a.add_action(tamper2)
    assert a.contains(tamper), "contains incorrect behavior"
    assert a.contains(tamper2), "contains incorrect behavior"
    remove_success = a.remove_action(tamper)
    assert remove_success
    assert not a.contains(tamper), "contains incorrect behavior"
    assert a.contains(tamper2), "contains incorrect behavior"
    a.add_action(tamper3)
    assert a.contains(tamper3), "contains incorrect behavior"
    assert len(a) == 2, "len incorrect return"
    remove_success = a.remove_action(tamper2)
    assert remove_success


def test_iter():
    """
    Tests iterator.
    """
    t = actions.trigger.Trigger(None, None, None)
    a = actions.tree.ActionTree("out", trigger=t)
    tamper = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="S")
    tamper2 = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="R")

    assert a.add_action(tamper)
    assert a.add_action(tamper2)
    assert not a.add_action(tamper)
    for node in a:
        print(node)


def test_run():
    """
    Tests running packets through the chain.
    """
    logger = logging.getLogger("test")
    t = actions.trigger.Trigger(None, None, None)
    a = actions.tree.ActionTree("out", trigger=t)
    tamper = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="S")
    tamper2 = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="R")
    duplicate = actions.duplicate.DuplicateAction()
    duplicate2 = actions.duplicate.DuplicateAction()
    drop = actions.drop.DropAction()

    packet = layers.packet.Packet(IP()/TCP())
    a.add_action(tamper)
    packets = a.run(packet, logging.getLogger("test"))
    assert len(packets) == 1
    assert None not in packets
    assert packets[0].get("TCP", "flags") == "S"
    a.add_action(tamper2)
    print(str(a))

    packet = layers.packet.Packet(IP()/TCP())
    assert not a.add_action(tamper), "tree added duplicate action"
    packets = a.run(packet, logging.getLogger("test"))
    assert len(packets) == 1
    assert None not in packets
    assert packets[0].get("TCP", "flags") == "R"
    print(str(a))

    a.remove_action(tamper2)
    a.remove_action(tamper)
    a.add_action(duplicate)
    packet = layers.packet.Packet(IP()/TCP(flags="RA"))
    packets = a.run(packet, logging.getLogger("test"))
    assert len(packets) == 2
    assert None not in packets
    assert packets[0][TCP].flags == "RA"
    assert packets[1][TCP].flags == "RA"
    print(str(a))

    duplicate.left = tamper
    duplicate.right = tamper2
    packet = layers.packet.Packet(IP()/TCP(flags="RA"))
    print("ABUT TO RUN")
    packets = a.run(packet, logging.getLogger("test"))
    assert len(packets) == 2
    assert None not in packets
    print(str(a))
    print(str(packets[0]))
    print(str(packets[1]))
    assert packets[0][TCP].flags == "S"
    assert packets[1][TCP].flags == "R"
    print(str(a))

    tamper.left = duplicate2
    packet = layers.packet.Packet(IP()/TCP(flags="RA"))
    packets = a.run(packet, logging.getLogger("test"))
    assert len(packets) == 3
    assert None not in packets
    assert packets[0][TCP].flags == "S"
    assert packets[1][TCP].flags == "S"
    assert packets[2][TCP].flags == "R"
    print(str(a))

    tamper2.left = drop
    packet = layers.packet.Packet(IP()/TCP(flags="RA"))
    packets = a.run(packet, logging.getLogger("test"))
    assert len(packets) == 2
    assert None not in packets
    assert packets[0][TCP].flags == "S"
    assert packets[1][TCP].flags == "S"
    print(str(a))

    assert a.remove_action(duplicate2)
    tamper.left = actions.drop.DropAction()
    packet = layers.packet.Packet(IP()/TCP(flags="RA"))
    packets = a.run(packet, logger )
    assert len(packets) == 0
    print(str(a))

    a.parse("[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:replace:14239},),duplicate(tamper{TCP:flags:replace:S},))-|", logger)
    packet = layers.packet.Packet(IP()/TCP(flags="A"))
    assert a.check(packet, logger)
    packets = a.run(packet, logger)
    assert len(packets) == 3
    assert packets[0][TCP].flags == "R"
    assert packets[1][TCP].flags == "S"
    assert packets[2][TCP].flags == "A"


def test_index():
    """
    Tests index
    """
    a = actions.tree.ActionTree("out")
    tamper = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="S")
    tamper2 = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="R")
    tamper3 = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="F")

    assert a.add_action(tamper)
    assert a[0] == tamper
    assert not a[1]
    assert a.add_action(tamper2)
    assert a[0] == tamper
    assert a[1] == tamper2
    assert a[-1] == tamper2
    assert not a[10]
    assert a.add_action(tamper3)
    assert a[-1] == tamper3
    assert not a[-11]

def test_mate():
    """
    Tests mate primitive
    """
    logger = logging.getLogger("test")
    t = actions.trigger.Trigger("field", "flags", "TCP")
    a = actions.tree.ActionTree("out", trigger=t)
    assert not a.choose_one()
    tamper = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="S")
    tamper2 = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="R")
    duplicate = actions.duplicate.DuplicateAction()
    duplicate2 = actions.duplicate.DuplicateAction()
    drop = actions.drop.DropAction()
    other_a = actions.tree.ActionTree("out", trigger=t)
    assert not a.mate(other_a), "Can't mate empty trees"
    assert a.add_action(tamper)
    assert other_a.add_action(tamper2)
    assert a.choose_one() == tamper
    assert other_a.choose_one() == tamper2
    assert a.get_parent(tamper) == (None, None)
    assert other_a.get_parent(tamper2) == (None, None)
    assert a.add_action(duplicate)
    assert a.get_parent(duplicate) == (tamper, "left")
    duplicate.right = drop
    assert a.get_parent(drop) == (duplicate, "right")
    assert other_a.add_action(duplicate2)
    # Test mating a full tree with a full tree
    assert str(a) == "[TCP:flags:0]-tamper{TCP:flags:replace:S}(duplicate(,drop),)-|"
    assert str(other_a) == "[TCP:flags:0]-tamper{TCP:flags:replace:R}(duplicate,)-|"
    assert a.swap(duplicate, other_a, duplicate2)
    assert str(a).strip() == "[TCP:flags:0]-tamper{TCP:flags:replace:S}(duplicate,)-|"
    assert str(other_a).strip() == "[TCP:flags:0]-tamper{TCP:flags:replace:R}(duplicate(,drop),)-|"
    assert len(a) == 2
    assert len(other_a) == 3
    assert duplicate2 not in other_a
    assert duplicate not in a
    assert tamper.left == duplicate2
    assert tamper2.left == duplicate
    assert other_a.get_parent(duplicate) == (tamper2, "left")
    assert a.get_parent(duplicate2) == (tamper, "left")
    assert other_a.get_parent(drop) == (duplicate, "right")
    assert a.get_parent(None) == (None, None)

    # Test mating two trees with just root nodes
    t = actions.trigger.Trigger("field", "flags", "TCP")
    a = actions.tree.ActionTree("out", trigger=t)
    assert not a.choose_one()
    tamper = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="S")
    tamper2 = actions.tamper.TamperAction(field="flags", tamper_type="replace", tamper_value="R")
    duplicate = actions.duplicate.DuplicateAction()
    duplicate2 = actions.duplicate.DuplicateAction()
    drop = actions.drop.DropAction()
    other_a = actions.tree.ActionTree("out", trigger=t)
    assert not a.mate(other_a)
    assert a.add_action(duplicate)
    assert other_a.add_action(duplicate2)
    assert a.mate(other_a)
    assert a.action_root == duplicate2
    assert other_a.action_root == duplicate
    assert not duplicate.left and not duplicate.right
    assert not duplicate2.left and not duplicate2.right
    # Confirm that no nodes have been aliased or connected between the trees
    for node in a:
        for other_node in other_a:
            assert not node.left == other_node
            assert not node.right == other_node

    # Test mating two trees where one is empty
    assert a.remove_action(duplicate2)
    # This should swap the duplicate action to be the action root of the other tree
    assert str(a) == "[TCP:flags:0]-|"
    assert str(other_a) == "[TCP:flags:0]-duplicate-|"
    assert a.mate(other_a)
    assert not other_a.action_root
    assert a.action_root == duplicate
    assert len(a) == 1
    assert len(other_a) == 0
    # Confirm that no nodes have been aliased or connected between the trees
    for node in a:
        for other_node in other_a:
            if other_node:
                assert not node.left == other_node
                assert not node.right == other_node

    assert a.parse("[TCP:flags:0]-tamper{TCP:flags:replace:S}(duplicate(,drop),)-|", logger)
    drop = a.action_root.left.right
    assert str(drop) == "drop"
    # Note that this will return a valid ActionTree, but because it is empty,
    # it is technically a False-y value, as it's length is 0
    assert other_a.parse("[TCP:flags:0]-|", logger) == other_a

    a.swap(drop, other_a, None)
    assert other_a.action_root == drop
    assert not a.action_root.left.right
    assert str(other_a) == "[TCP:flags:0]-drop-|"
    assert str(a) == "[TCP:flags:0]-tamper{TCP:flags:replace:S}(duplicate,)-|"
    other_a.swap(drop, a, a.action_root.left)
    # Confirm that no nodes have been aliased or connected between the trees
    for node in a:
        for other_node in other_a:
            if other_node:
                assert not node.left == other_node
                assert not node.right == other_node

    assert str(other_a) == "[TCP:flags:0]-duplicate-|"
    assert str(a) == "[TCP:flags:0]-tamper{TCP:flags:replace:S}(drop,)-|"

    a.parse("[TCP:flags:0]-drop-|", logger)
    other_a.parse("[TCP:flags:0]-duplicate(drop,drop)-|", logger)
    a_drop = a.action_root
    other_duplicate = other_a.action_root
    a.swap(a_drop, other_a, other_duplicate)
    print(str(a))
    print(str(other_a))
    assert str(other_a) == "[TCP:flags:0]-drop-|"
    assert str(a) == "[TCP:flags:0]-duplicate(drop,drop)-|"
    duplicate = actions.duplicate.DuplicateAction()
    duplicate2 = actions.duplicate.DuplicateAction()
    drop = actions.drop.DropAction()
    drop2 = actions.drop.DropAction()
    drop3 = actions.drop.DropAction()
    a = actions.tree.ActionTree("out", trigger=t)
    a.add_action(duplicate)
    a.add_action(drop)
    a.add_action(drop2)
    assert str(a) == "[TCP:flags:0]-duplicate(drop,drop)-|"
    assert a.get_slots() == 0
    other_a = actions.tree.ActionTree("out", trigger=t)
    other_a.add_action(drop3)
    a.swap(drop, other_a, drop3)
    assert str(a) == "[TCP:flags:0]-duplicate(drop,drop)-|"
    a.swap(drop3, other_a, drop)
    assert str(a) == "[TCP:flags:0]-duplicate(drop,drop)-|"

    assert a.mate(other_a)


def test_choose_one():
    """
    Tests choose_one functionality
    """
    a = actions.tree.ActionTree("out")
    drop = actions.drop.DropAction()
    assert not a.choose_one()
    assert a.add_action(drop)
    assert a.choose_one() == drop
    assert a.remove_action(drop)
    assert not a.choose_one()
    duplicate = actions.duplicate.DuplicateAction()
    a.add_action(duplicate)
    assert a.choose_one() == duplicate
    duplicate.left = drop
    assert a.choose_one() in [duplicate, drop]
    # Make sure that both actions get chosen
    chosen = set()
    for i in range(0, 10000):
        act = a.choose_one()
        chosen.add(act)
    assert chosen == set([duplicate, drop])
