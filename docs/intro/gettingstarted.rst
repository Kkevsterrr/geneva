Getting Started
=================

See our `website <https://censorship.ai>`_ or our `research papers <https://geneva.cs.umd.edu/papers>`_ for an in-depth read on how Geneva works. 

This documentation will provide a walkthrough of the main concepts behind Geneva, the main components of the codebase, and how they can be used. 

This section will give a high level overview on how Geneva works; before using it, you are **strongly recommended** to read through :ref:`How it Works`. 


What is a Strategy?
~~~~~~~~~~~~~~~~~~~

A censorship evasion strategy is simply a *description of how network traffic
should be modified*. A strategy is **not code**, it is a description that tells the
*strategy engine* how it should manipulate network traffic. 

The goal of a censorship evasion strategy is to modify the network traffic in a such a way that the censor is unable to censor it, but the client/server communication is unimpacted.

Strategies & Species
~~~~~~~~~~~~~~~~~~~~

Because Geneva commonly identifies many different strategies, we have defined a
*taxonomy* to classify strategies into.  

The Strategy taxonomy is as follows, ordered from most general to most specific:
 - 1. Species: The overarching bug a strategy exploits
 - 2. Subspecies: The mechanism used to exploit the bug
 - 3. Variant: Salient wireline differences using the same bug mechanism

The highest level classification is *species*,
a broad class of strategies classified by the type of weakness it exploits in a
censor implementation. :code:`TCB Teardown` is an example of one such species; if the
censor did not prematurely teardown TCBs, all the strategies in this species
would cease to function. 

Within each species, different *subspecies* represent
unique ways to exploit the weakness that defines the strategy. For example,
injecting an insertion TCP :code:`RST` packet would comprise one subspecies within the
TCB Teardown species; injecting a TCP :code:`FIN` would comprise another. 

Within each
subspecies, we further record *variants*, unique strategies that leverage the same
attack vector, but do so slightly differently: corrupting the checksum field on
a :code:`RST` packet is one variant of the :code:`TCB Teardown w/ RST` subspecies of the :code:`TCB Teardown` species;
corrupting the :code:`ack` field is another.  

We refer to specific individuals as *extinct*
if they once worked against a censor but are no longer effective (less than 5%
success rate). That formerly successful approaches could, after a few years, become
ineffective lends further motivation for a technique that can quickly learn new
strategies.


Running a Strategy
~~~~~~~~~~~~~~~~~~

For a fuller description of the DNA syntax, see :ref:`Censorship Evasion Strategies`.

.. code-block:: bash

    # python3 engine.py --server-port 80 --strategy "\/" --log debug
    2019-10-14 16:34:45 DEBUG:[ENGINE] Engine created with strategy \/ (ID bm3kdw3r) to port 80
    2019-10-14 16:34:45 DEBUG:[ENGINE] Configuring iptables rules
    2019-10-14 16:34:45 DEBUG:[ENGINE] iptables -A OUTPUT -p tcp --sport 80 -j NFQUEUE --queue-num 1
    2019-10-14 16:34:45 DEBUG:[ENGINE] iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 2
    2019-10-14 16:34:45 DEBUG:[ENGINE] iptables -A OUTPUT -p udp --sport 80 -j NFQUEUE --queue-num 1
    2019-10-14 16:34:45 DEBUG:[ENGINE] iptables -A INPUT -p udp --dport 80 -j NFQUEUE --queue-num 2


Note that if you have stale :code:`iptables` rules or other rules that rely on Geneva's default queues,
this will fail. To fix this, remove those rules.

Strategy Library
~~~~~~~~~~~~~~~~~

Geneva has found dozens of strategies that work against censors in China,
Kazakhstan, India, and Iran. We include several of these strategies in
`strategies.md <https://github.com/kkevsterrr/geneva>`_ . Note that this file contains success rates for
each individual country; a strategy that works in one country may not work as
well as other countries.

Researchers have observed that strategies may have differing success rates based
on your exact location. Although we have not observed this from our vantage
points, you may find that some strategies may work differently in a country we
have tested. If this is the case, don't be alarmed. However, please feel free to
reach out to a member of the team directly or open an issue on this page so we
can track how the strategies work from other geographic locations.

Disclaimer
==========

Running these strategies may place you at risk if you use it within a censoring regime. Geneva takes overt actions that interfere with the normal operations of a censor and its strategies are detectable on the network. During the training process, Geneva will intentionally trip censorship many times. Geneva is not an anonymity tool, nor does it encrypt any traffic. Understand the risks of running Geneva in your country before trying it.
