Evolution
==========

Now that we have a concrete definition for a censorship evasion strategies and a way to use them, we can begin evolving new strategies with Geneva's genetic algorithm. 

A genetic algorithm is a type of machine learning inspired by natural selection. Over the course of many *generations*, it optimizes a numerical *fitness* score of individuals; within each generation, individuals that have a low fitness will not survive to the next generation, and those with a high fitness score will survive and propagate.   

Each individual in Geneva is a censorship evasion strategy. :code:`evolve.py` is the main driver for Geneva's genetic algorithm and maintains the population pool of these strategies.

Each generation is comprised of the following:
 1. Mutation/Crossover - randomly mutating/mating strategies in the pool
 2. Strategy Evaluation - assigning a numerical fitness score to each strategy - decides which strategies should live on to the next generation
 3. Selection - the selection process of which strategies should survive to the next generation

For more detail on mutation/crossover or the selection process, see `our papers <https://geneva.cs.umd.edu/papers>`_ or the code in :code:`evolve.py` for more detail. :code:`evolve.py` exposes options to control hyperparameters of mutation/crossover, as well as other advanced options for rejecting mutations it has seen before. 

Strategy evaluation is significantly more complex, and will be covered in depth in the next section.

For most of this documentation, we will show examples of using :code:`evolve.py` with the :code:`--eval-only <strategy_here>` option. This instructs :code:`evolve.py` not to start the full genetic algorithm, but to instead perform a single strategy evaluation with the given parameters. :code:`--eval-only` can be replaced with parameters to the genetic algorithm to start strategy evolution. 


Argument Parsing
^^^^^^^^^^^^^^^^

Geneva uses a pass-through system of argument parsing. Different parts of the system define which arguments they care about, and they will parse just those args out. 
If :code:`--help` is used, :code:`evolve.py` will collect the help messages for the relevant components (evaluator, plugins, etc).


Population Control
^^^^^^^^^^^^^^^^^^

The two most important command line options for controlling evolutions are :code:`--population` and
:code:`--generations`. These control the population size and number of generations evolution will
take place for, respectively.

Geneva will not automatically halt evolution after population convergence occurs.


Seeding Population
^^^^^^^^^^^^^^^^^^

Geneva allows you to seed the starting population pool of strategies using the :code:`--seed <strategy>` parameter. This will create the initial population pool with nothing but copies of the given strategy. Mutation is applied to each individual before evaluation begins, so the first generation is not solely one individual being evaluated over and over again. 
