# Geneva

Geneva is an artificial intelligence tool that defeats censorship by exploiting bugs in censors, such as those in China, India, and Kazakhstan. Unlike many other anti-censorship solutions which require assistance from outside the censoring regime (Tor, VPNs, etc.), Geneva runs strictly on the client.

Under the hood, Geneva uses a genetic algorithm to evolve censorship evasion strategies and has found several previously unknown bugs in censors. Geneva's strategies manipulate the client's packets to confuse the censor without impacting the client/server communication. This makes Geneva effective against many types of in-network censorship (though it cannot be used against IP-blocking censorship). 

This code release specifically contains the strategy engine used by Geneva, its Python API, and a subset of published strategies, so users and researchers can test and deploy Geneva's strategies. To learn more about how Geneva works, visit [How it Works](#How-it-Works). We will be releasing the genetic algorithm at a later date.

## Setup

Geneva has been developed and tested for Centos or Debian-based systems. Windows support is currently in beta and requires more testing, but is available in this repository. Due to limitations of netfilter and raw sockets, Geneva does not work on OS X at this time and requires *python3.6* on Linux (with more versions coming soon).

Install netfilterqueue dependencies (Linux):
```
# sudo apt-get install build-essential python-dev libnetfilter-queue-dev libffi-dev libssl-dev iptables python3-pip
```

Install Python dependencies (Linux):
```
# python3 -m pip install -r requirements_linux.txt
```

Install Python dependencies (Windows):
```
# python3 -m pip install -r requirements_windows.txt
```

## Running it

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

## Strategy Library

Geneva has found dozens of strategies that work against censors in China, Kazakhstan, and India. We include several of these strategies in [strategies.md](strategies.md). Note that this file contains success rates for each individual country; a strategy that works in one country may not work as well as other countries.

Researchers have observed that strategies may have differing success rates based on your exact location. Although we have not observed this from our vantage points, you may find that some strategies may work differently in a country we have tested. If this is the case, don't be alarmed. However, please feel free to reach out to a member of the team directly or open an issue on this page so we can track how the strategies work from other geographic locations.

## Disclaimer

Running these strategies may place you at risk if you use it within a censoring regime. Geneva takes overt actions that interfere with the normal operations of a censor and its strategies are detectable on the network. Geneva is not an anonymity tool, nor does it encrypt any traffic. Understand the risks of running Geneva in your country before trying it.

-------

## How it Works

See our paper for an in-depth read on how Geneva works. Below is a rundown of the format of Geneva's strategy DNA. 

### Strategy DNA

Geneva's strategies can be arbitrarily complicated, and it defines a well-formatted syntax for
expressing strategies to the engine.

A strategy is simply a _description of how network traffic should be modified_. A strategy is not
code, it is a description that tells the engine how it should operate over traffic. 

A strategy divides how it handles outbound and inbound packets: these are separated in the DNA by a 
"\\/". Specifically, the strategy format is `<outbound forest> \/ <inbound forest>`. If `\/` is not
present in a strategy, all of the action trees are in the outbound forest. 

Both forests are composed of action trees, and each forest is allowed an arbitrarily many trees. 

An action tree is comprised of a _trigger_ and a _tree_. The trigger describes _when_ the strategy
should run, and the tree describes what should happen when the trigger fires. Recall that Geneva
operates at the packet level, therefore all triggers are packet-level triggers. Action trees start
with a trigger, and always end with a `-|`. 

Triggers operate as exact-matches, are formatted as follows: `[<protocol>:<field>:<value>]`. For
example, the trigger: `[TCP:flags:S]` will run its corresponding tree whenever it sees a `SYN`
TCP packet. If the corresponding action tree is `[TCP:flags:S]-drop-|`, this action tree will cause
the engine to drop any `SYN` packets. `[TCP:flags:S]-duplicate-|` will cause the engine to
duplicate the SYN packet.

Depending on the type of action, some actions can have up to two children. These are represented
with the following syntax: `[TCP:flags:S]-duplicate(<left_child>,<right_child>)-|`, where
`<left_child>` and `<right_child>` themselves are trees. If `(,)` is not specified, any packets
that emerge from the action will be sent on the wire. 

Any action that has parameters associated with it contain those parameters in `{}`. Consider the
following strategy with `tamper`.
```
[TCP:flags:A]-duplicate(tamper{TCP:flags:replace:R},)-| \/
```
This strategy takes outbound `ACK` packets and duplicates them. To the first duplicate, it tampers
the packet by replacing the `TCP` `flags` field with `RST`, and does nothing to the second
duplicate. 

Note that due to NFQueue limitations, actions that introduce branching (fragment, duplicate) are
disabled for incoming action forests. 

-------

## Citation

If you like the work or plan to use it in your projects, please follow the guidelines in [citation.bib](https://github.com/Kkevsterrr/geneva/blob/master/citation.bib).

## Paper

See [our paper](http://geneva.cs.umd.edu/papers/geneva_ccs19.pdf) from CCS for an in-depth dive into how it works.

## Contributors

[Kevin Bock](https://github.com/Kkevsterrr)

[George Hughey](https://github.com/ecthros)

[Xiao Qiang](https://twitter.com/rockngo)

[Dave Levin](https://www.cs.umd.edu/~dml/)
