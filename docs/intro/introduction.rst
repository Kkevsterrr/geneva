Introduction
===================================

Geneva is an artificial intelligence tool that defeats censorship by exploiting
bugs in censors, such as those in China, India, and Kazakhstan. Unlike many
other anti-censorship solutions which require assistance from outside the
censoring regime (Tor, VPNs, etc.), Geneva runs strictly on one side of the
connection (either the client or server side).

Under the hood, Geneva uses a genetic algorithm to evolve censorship evasion
strategies and has found several previously unknown bugs in censors. Geneva's
strategies manipulate the network stream to confuse the censor without impacting
the client/server communication. This makes Geneva effective against many types
of in-network censorship (though it cannot be used against IP-blocking
censorship).

Geneva is composed of two high level components: its *genetic algorithm* (which
it uses to evolve new censorship evasion strategies) and its *strategy engine*
(which is uses to run an individual censorship evasion strategy over a network
connection).

Geneva's `Github page <https://github.com/kkevsterrr/geneva>`_ contains the
Geneva's full implementation: its genetic algorithm, strategy engine, Python
API, and a subset of published strategies. With these tools, users and
researchers alike can evolve new strategies or leverage existing strategies to
evade censorship. To learn more about how Geneva works, see :ref:`How it
Works`.

