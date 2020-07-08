How it Works
==============

See our `website <https://censorship.ai>`_ or our `research papers <https://geneva.cs.umd.edu/papers>`_ for an in-depth read on how Geneva works. 

This documentation will provide a walkthrough of the main concepts behind Geneva, the main components of the codebase, and how they can be used. 

Censorship Evasion Strategies
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A censorship evasion strategy is simply a *description of how network traffic should be modified*. A strategy is **not
code**, it is a description that tells Geneva's strategy engine how it should manipulate network traffic. 

The goal of a censorship evasion strategy is to modify the network traffic in a such a way that the censor is unable to censor it, but the client/server communication is unimpacted.

A censorship evasion strategy composed of one or more packet-level building blocks. Geneva's core building blocks are:

1. :code:`duplicate`: takes one packet and returns two copies of the packet
2. :code:`drop`: takes one packet and returns no packets (drops the packet)
3. :code:`tamper`: takes one packet and returns the modified packet
4. :code:`fragment`: takes one packet and returns two fragments or two segments

Since :code:`duplicate` and :code:`fragment` introduce *branching*, these actions are composed into a binary-tree structure called an *action tree*. 

Each tree also has a *trigger*. The trigger describes which packets the tree should run on, and the tree describes what should happen to each of those packets when the trigger fires. Once a trigger fires on a packet, it pulls the packet into the tree for modifications, and the packets that emerge from the tree are sent on the wire. Recall that Geneva operates at the packet level, therefore all triggers are packet-level triggers.

Multiple action trees together form a *forest*. Geneva handles outbound and inbound packets differently, so strategies are composed of two forests: an outbound forest and an inbound forest.

Consider the following example of a simple Geneva strategy.

.. code-block:: none

                       +---------------+             triggers on TCP packets with the flags 
                       |  TCP:flags:A  |         <-- field set to 'ACK' - matching packets  
                       +-------+-------+             are captured and pulled into the tree
                               |
                     +---------v---------+           makes two copies of the given packet.
                           duplicate             <-- the tree is processed with an inorder 
                     +---------+---------+           traversal, so the left side is run first
                               |
                 +-------------+------------+
                 |                          |
    +------------v----------+               v    <-- dupilcate has no right child
              tamper
      {TCP:flags:replace:R}      <-- parameters to this action describe how 
    +------------+----------+        the packet should be tampered
                 |
    +------------v----------+
              tamper
       {TCP:chksum:corrupt}
    +------------+----------+
                 |
                 v               <-- packets that emerge from an in-order traversal
                                     of the leaves are sent on the wire

Strategy DNA Syntax
^^^^^^^^^^^^^^^^^^^

These strategies can be arbitrarily complicated, and Geneva defines a well-formatted string syntax for
unambiguously expressing strategies.

A strategy divides how it handles outbound and inbound packets: these are separated in the DNA by a
"\\/". Specifically, the strategy format is :code:`<outbound forest> \/ <inbound forest>`. If :code:`\/` is not
present in a strategy, all of the action trees are in the outbound forest.

Both forests are composed of action trees, and each forest is allowed an arbitrarily many trees.

Action trees always start with a trigger, which is formatted as: :code:`[<protocol>:<field>:<value>]`. For example, the trigger: :code:`[TCP:flags:S]` will run its corresponding tree whenever it sees a :code:`TCP` packet with the :code:`flags` field set to :code:`SYN`. If the corresponding action tree is :code:`[TCP:flags:S]-drop-|`, this action tree will cause the engine to drop any :code:`SYN` packets. :code:`[TCP:flags:S]-duplicate-|` will cause the engine to duplicate any SYN packets. 

Triggers also can contain an optional 4th parameter for *gas*, which describes the number of times a trigger can fire. The triger :code:`[IP:version:4:4]` will run only on the first 4 IPv4 packets it sees. If the gas is negative, the trigger acts as a *bomb* trigger, which means the trigger will not fire until a certain number of applicable packets have been seen. For example, the trigger :code:`[IP:version:4:-2]` will trigger only after it has seen two matching packets (and it will not trigger on those first packets).

Syntactically, action trees end with :code:`-|`.

Depending on the type of action, some actions can have up to two children (such as :code:`duplicate`). These are represented
with the following syntax: :code:`[TCP:flags:S]-duplicate(<left_child>,<right_child>)-|`, where
:code:`<left_child>` and :code:`<right_child>` themselves are trees. If :code:`(,)` is not specified, any packets
that emerge from the action will be sent on the wire. If an action only has one child (such as :code:`tamper`), it is always the left child. :code:`[TCP:flags:S]-tamper{<parameters>}(<left_child>,)-|`

Actions that have parameters specify those parameters within :code:`{}`. For example, giving parameters to the :code:`tamper` action could look like: :code:`[TCP:flags:S]-tamper{TCP:flags:replace:A}-|`. This strategy would trigger on TCP :code:`SYN` packets and replace the TCP :code:`flags` field to :code:`ACK`.

Putting this all together, below is the strategy DNA representation of the above diagram:
:code:`[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \/`

Geneva has code to parse this strategy DNA into strategies that can be applied to network traffic using the engine.

.. note:: Due to limitations of Scapy and NFQueue, actions that introduce branching (:code:`fragment`, :code:`duplicate`) are disabled for incoming action forests.
