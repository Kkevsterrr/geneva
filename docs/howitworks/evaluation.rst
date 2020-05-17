Strategy Evaluation
===================

Strategy evaluation tries to answer the question, *"which censorship evasion
strategies should survive and propagate in the next generation?"* This is the
job of the evaluator (:code:`evaluator.py`). The :code:`evaluator` assigns a numerical
fitness score to each strategy based on a fitness function. The actual numerical
fitness score itself is unimportant: as long as a 'better' strategy has a higher
fitness score than a 'worse' strategy, our fitness function will be sound.
Specific fitness numbers will be used in this section as examples, but all that
matters is the _comparison_ between fitness scores. 

Since the goal of Geneva is to find a strategy that evades censorship, to test a
strategy, we can simply send a forbidden query through a censor with a strategy
running and see if the request gets censored. Geneva operates at the network
(TCP/IP) layer, so it is completely application agnostic: whether :code:`curl` or
Google Chrome is generating network traffic, the engine can capture and modify
it. 

Environment IDs
^^^^^^^^^^^^^^^

During each evaluation, every strategy under test is given a random identifier, called an 'environment id'. This is used to track each strategy during evaluation. As each strategy is evaluated, a log file is written out named after the environment ID. See :ref:`Logging` for more information on how logs are stored.


Plugins
^^^^^^^^

To allow for evolution for many different applications, Geneva has a system of
plugins (in `plugins/`). A plugin is used to drive an application to make a
forbidden request, and defines the fitness function for that application. These
plugins provide evaluator with a common interface to launch them and get the
fitness score back. 

Geneva provides some plugins with fitness functions for common protocols out of
the box.  Whenever the evaluator or :code:`evolve.py` is run, you must specify
which plugin it should use with :code:`--test-type <plugin>`, such as
:code:`--test-type http`.

Plugins can define a client and optionally a server. The client will attempt to
make a forbidden connection through the censor to an external server, or
optionally if run from another computer, to an instance of the server plugin. 

To evaluate a strategy, the evaluator will initialize the engine with the strategy, 
launch the plugin client, and record the fitness returned by the plugin. 

See :ref:`Adding New Plugins` for more details on how plugins work, how they can override behavior in the evaluator, and how to add new ones to Geneva.

Fitness Functions
=================

Unlike many other machine learning scenarios, we have no gradient to learn against; censors give us only a binary signal (censored or not) to learn from. Therefore, we can't just write a fitness function that will directly guide us to the answer. Instead, we will use the fitness function to encourage the genetic algorithm to search the space of strategies that keeps the TCP connection alive.

As mentioned above, this guide might have specific fitness #s in examples, but the actual numeric values are not important - what is important is that a "bad" strategy gets a lower fitness number than a "good" strategy. We will use the fitness function to define a hierarchy of strategies.

The comparison order used by Geneva, ordered from best to worst:
 - Strategy that does not get censored and generates a minimal number of packets, no unused triggers, and minimal size 
 - Strategy that does not get censored, but has unused actions, is too large, or imparts overhead 
 - Strategy that gets censored 
 - Strategy that does not trigger on any packets but gets censored 
 - Strategy that breaks the underlying TCP connection 
 - Empty strategy  

Accomplishing this hierarchy is relatively straightforward - when evaluating a strategy, we assign a numerical fitness score such that strategies can be compared to one another and will be sorted according to this list.

This is done to guide the genetic algorithm in its search through the space of strategies. For example, consider a population pool that has 4 empty strategies, and one strategy that breaks the TCP connection. After evaluation, the empty strategies would be killed off, and the strategy that runs is propagated. When the offspring of this strategy mutate, if one of them no longer breaks the underlying TCP connection, it will be considered more fit than the other strategies, and so on.

This hierarchy accomplishes a significant *search space reduction*. Instead of Geneva fuzzing the entire space of possible strategies (for which there are many!), it instead quickly eliminates strategies that break the underlying connection and encourages the genetic algorithm to concentrate effort on only those strategies that keep the underlying connection alive.

Said another way, this hierarchy allows Geneva to differentiate between a strategy shooting ourselves in the foot, and being caught by the censor.
