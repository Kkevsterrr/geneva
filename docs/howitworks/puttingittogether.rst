Putting it all Together
=======================

Now that we know how to leverage the framework, this short section will give a high level of
how to put it all together and run Geneva's genetic algorithm yourself. 

The two most important command line options for controlling evolutions are :code:`--population` and
:code:`--generations`. These control the population size and number of generations evolution will
take place for, respectively. 

Generally, these need not be very large. Geneva intentionally does strategy evaluation serially & slowly, so increasing the size dramatically will make evolution take longer. For our existing research papers, the population count rarely exceeded 300. 

For example, to run a client-side evolution against HTTP censorship with a population pool of 200 and 25 generations, the following can be used:

.. code-block:: none
 
    # python3 evolve.py --population 200 --generations 25 --test-type http --server forbidden.org

Before running any evolution, it is recommended to spot test the plugins against whatever censor is used as the adversary to confirm the fitness function properly sets up the desirable hierarchy of individuals as specified in :ref:`Fitness Functions`: strategies that break the connection get lower fitness than those that get censored, which get a lower fitness than those that succeed. 

And that's it!
