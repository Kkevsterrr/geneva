.. geneva documentation master file, created by
   sphinx-quickstart on Fri Apr 10 12:35:13 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Geneva's documentation!
==================================


**Disclaimer:** Running Geneva or Geneva's strategies may place you at risk if you use it within a censoring regime. Geneva takes overt actions that interfere with the normal operations of a censor and its strategies are detectable on the network. During the training process, Geneva will intentionally trip censorship many times. Geneva is not an anonymity tool, nor does it encrypt any traffic. Understand the risks of running Geneva in your country before trying it.

.. toctree::
   :caption: Getting Started:

   intro/introduction
   intro/setup
   intro/gettingstarted

.. toctree::
   :caption: Usage:

   howitworks/howitworks
   howitworks/engine
   howitworks/evolution
   howitworks/evaluation
   howitworks/evaluator
   howitworks/addingaworker
   howitworks/logging
   howitworks/testing
   howitworks/puttingittogether

.. toctree::
   :caption: Extending Geneva:

   extending/plugins
   extending/actions
   extending/contributing

.. toctree::
   :glob:
   :caption: API Reference:

   api/*
   api/actions/*
   api/plugins/*
