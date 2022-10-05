# Geneva [![Build Status](https://travis-ci.com/Kkevsterrr/geneva.svg?branch=master)](https://travis-ci.com/Kkevsterrr/geneva) [![codecov](https://codecov.io/gh/Kkevsterrr/geneva/branch/master/graph/badge.svg)](https://codecov.io/gh/Kkevsterrr/geneva) [![Documentation Status](https://readthedocs.org/projects/geneva/badge/?version=latest)](https://geneva.readthedocs.io/en/latest/?badge=latest)

**Are you using Geneva? If so, let us know! Shoot us an email at geneva@cs.umd.edu, or to use PGP, email us directly with our keys [on our website](https://geneva.cs.umd.edu/people/).**

Geneva is an artificial intelligence tool designed by researchers at the University of Maryland that defeats censorship by exploiting bugs in censors, such as those in China, India, and Kazakhstan. Unlike many other anti-censorship solutions which require assistance from outside the censoring regime (Tor, VPNs, etc.), Geneva runs strictly on one side of the connection (either the client or server side). Geneva should be considered a research project for researchers, and it is not built with a graphical user interface. 

Under the hood, Geneva uses a genetic algorithm to evolve censorship evasion strategies and has found several previously unknown bugs in censors. Geneva's strategies manipulate the network stream to confuse the censor without impacting the client/server communication. This makes Geneva effective against many types of in-network censorship (though it cannot be used against IP-blocking censorship). 

Geneva is composed of two high level components: its genetic algorithm (which it uses to evolve new censorship evasion strategies) and its strategy engine (which is uses to run an individual censorship evasion strategy over a network connection). 

This codebase contains the Geneva's full implementation: its genetic algorithm, strategy engine, Python API, and a subset of published strategies. With these tools, users and researchers alike can evolve new strategies or leverage existing strategies to evade censorship. To learn more about how Geneva works, see [How it Works](#How-it-Works) or checkout our [documentation](https://geneva.readthedocs.io). 

## Setup

Geneva has been developed and tested for Centos or Debian-based systems. Due to limitations of
netfilter and raw sockets, Geneva does not work on OS X or Windows at this time and requires *python3.6*.
More detailed setup instructions are available at our [documentation](https://geneva.readthedocs.io).

Install netfilterqueue dependencies:
```
# sudo apt-get install build-essential python-dev libnetfilter-queue-dev libffi-dev libssl-dev iptables python3-pip
```

Install Python dependencies:
```
# python3 -m pip install -r requirements.txt
```

On Debian 10 systems, some users have reported needing to install netfilterqueue directly from Github: 
```
# sudo python3 -m pip install --upgrade -U git+https://github.com/kti/python-netfilterqueue
```

## Running a Strategy

A censorship evasion strategy is simply a _description of how network traffic should be modified_. A strategy is not
code, it is a description that tells the engine how it should operate over traffic. For a fuller description of the DNA syntax, see [Censorship Evasion Strategies](#Censorship-Evasion-Strategies).

```
# python3 engine.py --server-port 80 --strategy "[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:corrupt},),)-|" --log debug
2019-10-14 16:34:45 DEBUG:[ENGINE] Engine created with strategy \/ (ID bm3kdw3r) to port 80
2019-10-14 16:34:45 DEBUG:[ENGINE] Configuring iptables rules
2019-10-14 16:34:45 DEBUG:[ENGINE] iptables -A OUTPUT -p tcp --sport 80 -j NFQUEUE --queue-num 1
2019-10-14 16:34:45 DEBUG:[ENGINE] iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 2
2019-10-14 16:34:45 DEBUG:[ENGINE] iptables -A OUTPUT -p udp --sport 80 -j NFQUEUE --queue-num 1
2019-10-14 16:34:45 DEBUG:[ENGINE] iptables -A INPUT -p udp --dport 80 -j NFQUEUE --queue-num 2
```

Note that if you have stale `iptables` rules or other rules that rely on Geneva's default queues,
this will fail. To fix this, remove those rules.

Also note that if you want to specify multiple ports for Geneva to monitor, you can specify a port range using `--server-port 4000:5000` to monitor all ports in the range 4000-5000, or you can specify a list like `--server-port 80,443,4444` to only monitor the explicit ports given.

## Strategy Library

Geneva has found dozens of strategies that work against censors in China, Kazakhstan, India, and Iran. We include several of these strategies in [strategies.md](strategies.md). Note that this file contains success rates for each individual country; a strategy that works in one country may not work as well as other countries.

Researchers have observed that strategies may have differing success rates based on your exact location. Although we have not observed this from our vantage points, you may find that some strategies may work differently in a country we have tested. If this is the case, don't be alarmed. However, please feel free to reach out to a member of the team directly or open an issue on this page so we can track how the strategies work from other geographic locations.

## Disclaimer

Running these strategies may place you at risk if you use it within a censoring regime. Geneva takes overt actions that interfere with the normal operations of a censor and its strategies are detectable on the network. During the training process, Geneva will intentionally trip censorship many times. Geneva is not an anonymity tool, nor does it encrypt any traffic. Understand the risks of running Geneva in your country before trying it.

-------

# How it Works

See our [paper](#Paper) for an in-depth read on how Geneva works. Below is a walkthrough of the main concepts behind Geneva, the major components of the codebase, and how they can be used. 

## Censorship Evasion Strategies

A censorship evasion strategy is simply a _description of how network traffic should be modified_. A strategy is _not
code_, it is a description that tells Geneva's stratgy engine how it should manipulate network traffic. The goal of a censorship evasion strategy is to modify the network traffic in a such a way that the censor is unable to censor it, but the client/server communication is unimpacted.  

A censorship evasion strategy composed of one or more packet-level building blocks. Geneva's core building blocks are:
1. `duplicate`: takes one packet and returns two copies of the packet
2. `drop`: takes one packet and returns no packets (drops the packet)
3. `tamper`: takes one packet and returns the modified packet
4. `fragment`: takes one packet and returns two fragments or two segments

Since `duplicate` and `fragment` introduce _branching_, these actions are composed into a binary-tree structure called an _action tree_. Each tree also has a _trigger_. The trigger describes which packets the tree should run on, and the tree describes what should happen to each of those packets when the trigger fires. Once a trigger fires on a packet, it pulls the packet into the tree for modifications, and the packets that emerge from the tree are sent on the wire. Recall that Geneva operates at the packet level, therefore all triggers are packet-level triggers. 

Multiple action trees together form a _forest_. Geneva handles outbound and inbound packets differently, so strategies are composed of two forests: an outbound forest and an inbound forest.

Consider the following example of a simple Geneva strategy. 
```       
                   +---------------+
                   |  TCP:flags:A  |         <-- triggers on TCP packets with the flags field set to 'ACK'
                   +-------+-------+             matching packets are captured and pulled into the tree
                           |
                 +---------v---------+
                       duplicate             <-- makes two copies of the given packet. the tree is processed 
                 +---------+---------+           with an inorder traversal, so the left side is run first
                           |
             +-------------+------------+
             |                          |
+------------v----------+               v    <-- dupilcate has no right child, so this packet will be sent on the wire unimpacted
          tamper              
  {TCP:flags:replace:R}      <-- parameters to this action describe how the packet should be tampered 
+------------+----------+
             |
+------------v----------+
          tamper
   {TCP:chksum:corrupt}
+------------+----------+
             |
             v               <-- packets that emerge from an in-order traversal of the leaves are sent on the wire

```

This strategy triggers on `TCP` packets with the `flags` field set to `ACK`. It makes a duplicate of the `ACK` packet; the first duplicate has its flags field changed to `RST` and its checksum (`chksum`) field corrupted; the second duplicate is unchaged. Both packets are then sent on the network. 

### Strategy DNA

These strategies can be arbitrarily complicated, and Geneva defines a well-formatted string syntax for
unambiguously expressing strategies.

A strategy divides how it handles outbound and inbound packets: these are separated in the DNA by a 
"\\/". Specifically, the strategy format is `<outbound forest> \/ <inbound forest>`. If `\/` is not
present in a strategy, all of the action trees are in the outbound forest. 

Both forests are composed of action trees, and each forest is allowed an arbitrarily many trees. 

Action trees always start with a trigger, which is formatted as: `[<protocol>:<field>:<value>]`. For example, the trigger: `[TCP:flags:S]` will run its corresponding tree whenever it sees a `TCP` packet with the `flags` field set to `SYN`. If the corresponding action tree is `[TCP:flags:S]-drop-|`, this action tree will cause the engine to drop any `SYN` packets. `[TCP:flags:S]-duplicate-|` will cause the engine to duplicate any SYN packets. 

Syntactically, action trees end with `-|`.

Depending on the type of action, some actions can have up to two children (such as `duplicate`). These are represented
with the following syntax: `[TCP:flags:S]-duplicate(<left_child>,<right_child>)-|`, where
`<left_child>` and `<right_child>` themselves are trees. If `(,)` is not specified, any packets
that emerge from the action will be sent on the wire. If an action only has one child (such as `tamper`), it is always the left child. `[TCP:flags:S]-tamper{<parameters>}(<left_child>,)-|`

Actions that have parameters specify those parameters within `{}`. For example, giving parameters to the `tamper` action could look like: `[TCP:flags:S]-tamper{TCP:flags:replace:A}-|`. This strategy would trigger on TCP `SYN` packets and replace the TCP `flags` field to `ACK`. 

Putting this all together, below is the strategy DNA representation of the above diagram:
```
[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \/
```

Geneva has code to parse this strategy DNA into strategies that can be applied to network traffic using the engine. 

Note that due to limitations of Scapy and NFQueue, actions that introduce branching (`fragment`, `duplicate`) are
disabled for incoming action forests. 

## Engine

The strategy engine (`engine.py`) applies a strategy to a network connection. The engine works by capturing all traffic to/from a specified port. Packets that match an active trigger are run through the associated action-tree, and packets that emerge from the tree are sent on the wire. 

The engine also has a Python API for using it in your application. It can be used as a context manager or invoked in the background as a thread. 
For example, consider the following simple application. 

```python
import os
import engine

# Port to run the engine on
port = 80
# Strategy to use
strategy = "[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),)-| \/"

# Create the engine in debug mode
with engine.Engine(port, strategy, log_level="debug") as eng:
    os.system("curl http://example.com?q=ultrasurf")
```
This script creates an instance of the engine with a specified strategy, and that strategy will be running for everything within the context manager. When the context manager exits, the engine will clean itself up. See the `examples/` folder for more use cases of the engine. 

Due to limitations of scapy and NFQueue, the engine cannot be used to communicate with localhost.

## Citation

If you like the work or plan to use it in your projects, please follow the guidelines in [citation.bib](https://github.com/Kkevsterrr/geneva/blob/master/citation.bib).

## Paper

See [our paper](http://geneva.cs.umd.edu/papers/geneva_ccs19.pdf) from CCS or the rest of [our papers and talks](http://geneva.cs.umd.edu/papers/) for an in-depth dive into how Geneva works and how it can be applied.

## Contributors

[Kevin Bock](https://github.com/Kkevsterrr)

[George Hughey](https://github.com/ecthros)

[Xiao Qiang](https://twitter.com/rockngo)

[Dave Levin](https://www.cs.umd.edu/~dml/)
