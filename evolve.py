"""
Main evolution driver for Geneva (GENetic EVAsion). This file performs the genetic algorithm,
and relies on the evaluator (evaluator.py) to provide fitness evaluations of each individual.
"""

import argparse
import copy
import logging
import operator
import os
import random
import subprocess as sp
import sys

import actions.strategy
import actions.tree
import actions.trigger
import evaluator
import layers.packet

# Grab the terminal size for printing
try:
    _, COLUMNS = sp.check_output(['stty', 'size']).decode().split()
# If pytest has capturing enabled or this is run without a tty, catch the exception
except sp.CalledProcessError:
    _, COLUMNS = 0, 0


def setup_logger(log_level):
    """
    Sets up the logger. This will log at the specified level to "ga.log" and at debug level to "ga_debug.log".
    Logs are stored in the trials/ directory under a run-specific folder.
    Example: trials/2020-01-01_01:00:00/logs/ga.log

    Args:
        log_level (str): Log level to use in setting up the logger ("debug")
    """
    level = log_level.upper()
    assert level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], "Unknown log level %s" % level
    actions.utils.CONSOLE_LOG_LEVEL = level.lower()

    # Setup needed folders
    ga_log_dir = actions.utils.setup_dirs(actions.utils.RUN_DIRECTORY)

    ga_log = os.path.join(ga_log_dir, "ga.log")
    ga_debug_log = os.path.join(ga_log_dir, "ga_debug.log")

    # Configure logging globally
    formatter = logging.Formatter(fmt='%(asctime)s %(levelname)s:%(message)s', datefmt="%Y-%m-%d %H:%M:%S")
    logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s', datefmt="%Y-%m-%d %H:%M:%S")

    # Set up the root logger
    logger = logging.getLogger("ga_%s" % actions.utils.RUN_DIRECTORY)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    setattr(logger, "ga_log_dir", ga_log_dir)

    # If this logger's handlers have already been set up, don't add them again
    if logger.handlers:
        return logger

    # Set log level of console
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(formatter)
    logger.addHandler(console)

    # Add a DEBUG file handler to send all the debug output to a file
    debug_file_handler = logging.FileHandler(ga_debug_log)
    debug_file_handler.setFormatter(formatter)
    debug_file_handler.setLevel(logging.DEBUG)
    logger.addHandler(debug_file_handler)

    # Add a file handler to send all the output to a file
    file_handler = logging.FileHandler(ga_log)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)
    logger.addHandler(file_handler)
    return logger


def collect_plugin_args(cmd, plugin, plugin_type, message=None):
    """
    Collects and prints arguments for a given plugin.

    Args:
        cmd (list): sys.argv or a list of args to parse
        plugin (str): Name of plugin to import ("http")
        plugin_type (str): Component of plugin to import ("client")
        message (str): message to override for printing
    """
    if not message:
        message = plugin_type
    try:
        _, cls = actions.utils.import_plugin(plugin, plugin_type)
        print("\n\n")
        print("=" * int(COLUMNS))
        print("Options for --test-type %s %s" % (plugin, message))
        cls.get_args(cmd)
    # Catch SystemExit here, as this is what argparse raises when --help is passed
    except (SystemExit, Exception):
        pass


def get_args(cmd):
    """
    Sets up argparse and collects arguments.

    Args:
        cmd (list): sys.argv or a list of args to parse

    Returns:
        namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(description='Genetic algorithm for evolving censorship evasion.\n\nevolve.py uses a pass-through argument system to pass the command line arguments through different files in the system, including the evaluator (evaluator.py) and a given plugin (plugins/). --help will collect all these arguments.', add_help=False, prog="evolve.py")

    parser.add_argument('--test-type', action='store', choices=actions.utils.get_plugins(), default="http", help="plugin to launch")

    # Add help message separately so we can collect the help messages of all of the other parsers
    parser.add_argument('-h', '--help', action='store_true', default=False, help='print this help message and exit')

    # Control aspects of individuals
    ind_group = parser.add_argument_group('control aspects of individual strategies')
    ind_group.add_argument('--in-trees', action='store', type=int, default=0, help='starting # of input-direction action trees per strategy. Disables inbound forest if set to 0')
    ind_group.add_argument('--out-trees', action='store', type=int, default=1, help='starting # of output-direction action trees per strategy')
    ind_group.add_argument('--in-actions', action='store', type=int, default=2, help='starting # of input-direction actions per action tree')
    ind_group.add_argument('--out-actions', action='store', type=int, default=2, help='starting # of output-direction actions per action tree')
    ind_group.add_argument('--fix-trigger', action='store', help='fix all triggers for this evolution to a given trigger')

    # Options to control the population pool
    pop_group = parser.add_argument_group('control aspects of the population pool')
    pop_group.add_argument('--load-from', action='store', help="Load population from a generation file")
    pop_group.add_argument('--seed', action='store', help='seed strategy to initialize the population to.')

    # Options to evaluate and exit, skip evaluation, and to specify the type of test
    evaluation_group = parser.add_argument_group('control aspects of strategy evaluation')
    evaluation_group.add_argument('--eval-only', action='store', default=None, help='only evaluate fitness for a given strategy or file of strategies')
    evaluation_group.add_argument('--no-eval', action='store_true', help="Disable evaluator for debugging")
    evaluation_group.add_argument('--runs', action='store', type=int, default=1, help='number of times each strategy should be run for one evaluation (default 1, fitness is averaged).')

    # Hyperparameters for genetic algorithm
    genetic_group = parser.add_argument_group('control aspects of the genetic algorithm')
    genetic_group.add_argument('--elite-clones', action='store', type=int, default=3, help='number copies of the highest performing individual that should be propagated to the next generation.')
    genetic_group.add_argument('--mutation-pb', action='store', type=float, default=0.99, help='mutation probability')
    genetic_group.add_argument('--crossover-pb', action='store', type=float, default=0.4, help='crossover probability')
    genetic_group.add_argument('--allowed-retries', action='store', type=int, default=20, help='maximum number of times GA will generate any given individual')
    genetic_group.add_argument('--generations', type=int, action='store', default=50, help="number of generations to run for.")
    genetic_group.add_argument('--population', type=int, action='store', default=250, help="size of population.")
    genetic_group.add_argument('--no-reject-empty', action='store_true', default=False, help="disable mutation rejection of empty strategies")
    genetic_group.add_argument('--no-canary', action='store_true', help="disable canary phase")

    # Limit access to certain protocols, fields, actions, or types of individuals
    filter_group = parser.add_argument_group('limit access to certain protocols, fields, actions, or types of individuals')
    filter_group.add_argument('--protos', action="store", default="TCP", help="allow the GA to scope only to these protocols")
    filter_group.add_argument('--fields', action='store', default="", help='restrict the GA to only seeing given fields')
    filter_group.add_argument('--disable-fields', action='store', default="", help='restrict the GA to never using given fields')
    filter_group.add_argument('--no-gas', action="store_true", help="disables trigger gas")
    filter_group.add_argument('--disable-action', action='store', default="sleep,trace", help='disables specific actions')

    # Logging
    logging_group = parser.add_argument_group('control logging')
    logging_group.add_argument('--log', action='store', default="info", choices=("debug", "info", "warning", "critical", "error"), help="Sets the log level")
    logging_group.add_argument('--no-print-hall', action='store_true', help="does not print hall of fame at the end")
    logging_group.add_argument('--graph-trees', action='store_true', default=False, help='graph trees in addition to outputting to screen')

    # Misc
    usage_group = parser.add_argument_group('misc usage')
    usage_group.add_argument('--no-lock-file', default=(os.name == "posix"), action='store_true', help="does not use /lock_file.txt")
    usage_group.add_argument('--force-cleanup', action='store_true', default=False, help='cleans up all docker containers and networks after evolution')

    if not cmd:
        parser.error("No arguments specified")

    args, _ = parser.parse_known_args(cmd)

    epilog = "See the README.md for usage."
    # Override the help message to collect the pass through args
    if args.help:
        parser.print_help()
        print(epilog)
        print("=" * int(COLUMNS))
        print("\nevolve.py uses a pass-through argument system to evaluator.py and other parts of Geneva. These arguments are below.\n\n")
        evaluator.get_arg_parser(cmd).print_help()
        if args.test_type:
            collect_plugin_args(cmd, args.test_type, "plugin", message="parent plugin")
            collect_plugin_args(cmd, args.test_type, "client")
            collect_plugin_args(cmd, args.test_type, "server")
        raise SystemExit
    return args


def fitness_function(logger, population, ga_evaluator):
    """
    Calls the evaluator to evaluate a given population of strategies.
    Sets the .fitness attribute of each individual.

    Args:
        logger (:obj:`logging.Logger`): A logger to log with
        population (list): List of individuals to evaluate
        ga_evaluator (:obj:`evaluator.Evaluator`): An evaluator object to evaluate with

    Returns:
        list: Population post-evaluation
    """
    if ga_evaluator:
        return ga_evaluator.evaluate(population)

    for ind in population:
        ind.fitness = 0
        logger.info("[%s] Fitness %d: %s", -1, ind.fitness, str(ind))

    return population


def sel_random(individuals, k):
    """
    Implementation credit to DEAP: https://github.com/DEAP/deap
    Select *k* individuals at random from the input *individuals* with
    replacement. The list returned contains references to the input
    *individuals*.

    Args:
        individuals (list): A list of individuals to select from.
        k (int): The number of individuals to select.

    Returns:
        list: A list of selected individuals.
    """
    return [random.choice(individuals) for _ in range(k)]


def selection_tournament(individuals, k, tournsize, fit_attr="fitness"):
    """
    Implementation credit to DEAP: https://github.com/DEAP/deap
    Select the best individual among *tournsize* randomly chosen
    individuals, *k* times. The list returned contains
    references to the input *individuals*.

    Args:
        individuals (list): A list of individuals to select from.
        k (int): The number of individuals to select.
        tournsize (int): The number of individuals participating in each tournament.
        fit_attr: The attribute of individuals to use as selection criterion (defaults to "fitness")

    Returns:
        list: A list of selected individuals.
    """
    chosen = []
    for _ in range(k):
        aspirants = sel_random(individuals, tournsize)
        chosen.append(copy.deepcopy(max(aspirants, key=operator.attrgetter(fit_attr))))
    return chosen


def get_unique_population_size(population):
    """
    Computes number of unique individuals in a population.

    Args:
        population (list): Population list
    """
    uniques = {}
    for ind in population:
        uniques[str(ind)] = True
    return len(list(uniques.keys()))


def add_to_hof(hof, population):
    """
    Iterates over the current population and updates the hall of fame.
    The hall of fame is a dictionary that tracks the fitness of every
    run of every strategy ever.

    Args:
        hof (dict): Current hall of fame
        population (list): Population list

    Returns:
        dict: Updated hall of fame
    """
    for ind in population:
        if str(ind) not in hof:
            hof[str(ind)] = []
        hof[str(ind)].append(ind.fitness)

    return hof


def generate_strategy(logger, num_in_trees, num_out_trees, num_in_actions, num_out_actions, seed, environment_id=None, disabled=None):
    """
    Generates a strategy individual.

    Args:
        logger (:obj:`logging.Logger`): A logger to log with
        num_in_trees (int): Number of trees to initialize in the inbound forest
        num_out_trees (int): Number of trees to initialize in the outbound forest
        num_in_actions (int): Number of actions to initialize in the each inbound tree
        num_out_actions (int): Number of actions to initialize in the each outbound tree
        environment_id (str, optional): Environment ID to assign to the new individual
        disabled (str, optional): List of actions that should not be considered in building a new strategy

    Returns:
        :obj:`actions.strategy.Strategy`: A new strategy object
    """
    try:
        strat = actions.strategy.Strategy([], [], environment_id=environment_id)
        strat.initialize(logger, num_in_trees, num_out_trees, num_in_actions, num_out_actions, seed, disabled=disabled)
    except Exception:
        logger.exception("Failure to generate strategy")
        raise

    return strat


def mutation_crossover(logger, population, hall, options):
    """
    Apply crossover and mutation on the offspring.

    Hall is a copy of the hall of fame, used to accept or reject mutations.

    Args:
        logger (:obj:`logging.Logger`): A logger to log with
        population (list): Population of individuals
        hall (dict): Current hall of fame
        options (dict): Options to override settings. Accepted keys are:
            "crossover_pb" (float): probability of crossover
            "mutation_pb" (float): probability of mutation
            "allowed_retries" (int): number of times a strategy is allowed to exist in the hall of fame.
            "no_reject_empty" (bool): whether or not empty strategies should be rejected

    Returns:
        list: New population after mutation
    """
    cxpb = options.get("crossover_pb", 0.5)
    mutpb = options.get("mutation_pb", 0.5)

    offspring = copy.deepcopy(population)
    for i in range(1, len(offspring), 2):
        if random.random() < cxpb:
            ind = offspring[i - 1]
            actions.strategy.mate(ind, offspring[i], indpb=0.5)
            offspring[i - 1].fitness, offspring[i].fitness = -1000, -1000

    for i in range(len(offspring)):
        if random.random() < mutpb:

            mutation_accepted = False
            while not mutation_accepted:
                test_subject = copy.deepcopy(offspring[i])
                mutate_individual(logger, test_subject)

                # Pull out some metadata about this proposed mutation
                fitness_history = hall.get(str(test_subject), [])

                # If we've seen this strategy 10 times before and it has always failed,
                # or if we have seen it 20 times already, or if it is an empty strategy,
                # reject this mutation and get another
                if len(fitness_history) >= 10 and all(fitness < 0 for fitness in fitness_history) or \
                   len(fitness_history) >= options.get("allowed_retries", 20) or \
                   (len(test_subject) == 0 and not options.get("no_reject_empty")):
                    mutation_accepted = False
                else:
                    mutation_accepted = True

            offspring[i] = test_subject
            offspring[i].fitness = -1000

    return offspring


def mutate_individual(logger, ind):
    """
    Simply calls the mutate function of the given individual.

    Args:
        logger (:obj:`logging.Logger`): A logger to log with
        ind (:obj:`actions.strategy.Strategy`): A strategy individual to mutate

    Returns:
        :obj:`actions.strategy.Strategy`: Mutated individual
    """
    return ind.mutate(logger)


def run_collection_phase(logger, ga_evaluator):
    """Individual mutation works best when it has seen real packets to base
    action and trigger values off of, instead of blindly fuzzing packets.
    Usually, the 0th generation is useless because it hasn't seen any real
    packets yet, and it bases everything off fuzzed data. To combat this, a
    canary phase is done instead.

    In the canary phase, a single dummy individual is evaluated to capture
    packets. Once the packets are captured, they are associated with all of the
    initial population pool, so all of the individuals have some packets to base
    their data off of.

    Since this phase by necessity requires the evaluator, this is only run if
    --no-eval is not specified.

    Args:
        logger (:obj:`logging.Logger`): A logger to log with
        ga_evaluator (:obj:`evaluator.Evaluator`): An evaluator object to evaluate with

    Returns:
        str: ID of the test 'canary' strategy evaluated to do initial collection
    """
    canary = generate_strategy(logger, 0, 0, 0, 0, None, disabled=[])
    canary_id = ga_evaluator.canary_phase(canary)
    if not canary_id:
        return []
    return canary_id


def write_generation(filename, population):
    """
    Writes the population pool for a specific generation.

    Args:
        filename (str): Name of file to write the generation out to
        population (list): List of individuals to write out
    """
    # Open File as writable
    with open(filename, "w") as fd:
        # Write each individual to file
        for index, individual in enumerate(population):
            if index == len(population) - 1:
                fd.write(str(individual))
            else:
                fd.write(str(individual) + "\n")


def load_generation(logger, filename):
    """
    Loads strategies from a file

    Args:
        logger (:obj:`logger.Logger`): A logger to log with
        filename (str): Filename of file containing newline separated strategies
            to read generation from
    """
    population = []
    with open(filename) as file:

        # Read each individual from file
        for individual in file:
            strategy = actions.utils.parse(individual, logger)
            population.append(strategy)

    return population


def initialize_population(logger, options, canary_id, disabled=None):
    """
    Initializes the population from either random strategies or strategies
    located in a file.

    Args:
        logger (:obj:`logging.Logger`): A logger to log with
        options (dict): Options to respect in generating initial population.
            Options that can be specified as keys:

            "load_from" (str, optional): File to load population from
            population_size (int): Size of population to initialize

            "in-trees" (int): Number of trees to initialize in inbound forest
            of each individual

            "out-trees" (int): Number of trees to initialize in outbound forest
            of each individual

            "in-actions" (int): Number of actions to initialize in each
            inbound tree of each individual

            "out-actions" (int): Number of actions to initialize in each
            outbound tree of each individual

            "seed" (str): Strategy to seed this pool with
        canary_id (str): ID of the canary strategy, used to associate each new
            strategy with the packets captured during the canary phase
        disabled (list, optional): List of actions that are disabled

    Returns:
        list: New population of individuals
    """

    if options.get("load_from"):
        # Load the population from a file
        return load_generation(logger, options["load_from"])

    # Generate random strategies
    population = []

    for _ in range(options["population_size"]):
        p = generate_strategy(logger, options["in-trees"], options["out-trees"], options["in-actions"],
                              options["out-actions"], options["seed"], environment_id=canary_id,
                              disabled=disabled)
        population.append(p)

    return population


def genetic_solve(logger, options, ga_evaluator):
    """
    Run genetic algorithm with given options.

    Args:
        logger (:obj:`logging.Logger`): A logger to log with
        options (dict): Options to respect.
        ga_evaluator (:obj:`evaluator.Evaluator`): Evaluator to evaluate
            strategies with

    Returns:
        dict: Hall of fame of individuals
    """
    # Directory to save off each generation so evolution can be resumed
    ga_generations_dir = os.path.join(actions.utils.RUN_DIRECTORY, "generations")

    hall = {}
    canary_id = None
    if ga_evaluator and not options["no-canary"]:
        canary_id = run_collection_phase(logger, ga_evaluator)
    else:
        logger.info("Skipping initial collection phase.")

    population = initialize_population(logger, options, canary_id, disabled=options["disable_action"])

    try:
        offspring = []
        elite_clones = []
        if options["seed"]:
            elite_clones = [actions.utils.parse(options["seed"], logger)]

        # Evolution over given number of generations
        for gen in range(options["num_generations"]):
            # Debug printing
            logger.info("="*(int(COLUMNS) - 25))
            logger.info("Generation %d:", gen)

            # Save current population pool
            filename = os.path.join(ga_generations_dir, "generation" + str(gen) + ".txt")
            write_generation(filename, population)

            # To store the best individuals of this generation to print
            best_fit, best_ind = -10000, None

            # Mutation and crossover
            offspring = mutation_crossover(logger, population, hall, options)
            offspring += elite_clones

            # Calculate fitness
            offspring = fitness_function(logger, offspring, ga_evaluator)

            total_fitness = 0
            # Iterate over the offspring to find the best individual for printing
            for ind in offspring:
                if ind.fitness is None and ga_evaluator:
                    logger.error("No fitness for individual found: %s.", str(ind))
                    continue
                total_fitness += ind.fitness
                if ind.fitness is not None and ind.fitness >= best_fit:
                    best_fit = ind.fitness
                    best_ind = ind

            # Check if any individuals of this generation belong in the hall of fame
            hall = add_to_hof(hall, offspring)

            # Save current hall of fame
            filename = os.path.join(ga_generations_dir, "hall" + str(gen) + ".txt")
            write_hall(filename, hall)

            # Status printing for this generation
            logger.info("\nGeneration: %d | Unique Inviduals: %d | Avg Fitness: %d | Best Fitness [%s] %s: %s",
                        gen, get_unique_population_size(population), round(total_fitness / float(len(offspring)), 2),
                        best_ind.environment_id, str(best_fit), str(best_ind))

            # Select next generation
            population = selection_tournament(offspring, k=len(offspring) - options["elite_clones"], tournsize=10)

            # Add the elite clones
            if options["elite_clones"] > 0:
                elite_clones = [copy.deepcopy(best_ind) for x in range(options["elite_clones"])]

    # If the user interrupted, try to gracefully shutdown
    except KeyboardInterrupt:
        # Only need to stop the evaluator if one is defined
        if ga_evaluator:
            ga_evaluator.stop = True
        logger.info("")

    finally:
        if options["force_cleanup"]:
            # Try to clean up any hanging docker containers/networks from the run
            logger.warning("Cleaning up docker...")
            try:
                sp.check_call("docker stop $(docker ps -aq) > /dev/null 2>&1", shell=True)
            except sp.CalledProcessError:
                pass

    return hall


def collect_results(hall_of_fame):
    """
    Collect final results from offspring.

    Args:
        hall_of_fame (dict): Hall of fame of individuals

    Returns:
        str: Formatted printout of the hall of fame
    """
    # Sort first on number of runs, then by fitness.
    best_inds = sorted(hall_of_fame, key=lambda ind: (len(hall_of_fame[ind]), sum(hall_of_fame[ind])/len(hall_of_fame[ind])))
    output = "Results: \n"
    for ind in best_inds:
        sind = str(ind)
        output += "Avg. Fitness %s: %s (Evaluated %d times: %s)\n" % (sum(hall_of_fame[sind])/len(hall_of_fame[sind]), sind, len(hall_of_fame[sind]), hall_of_fame[sind])
    return output


def print_results(hall_of_fame, logger):
    """
    Prints hall of fame.

    Args:
        hall_of_fame (dict): Hall of fame to print
        logger (:obj:`logging.Logger`): A logger to log results with
    """
    logger.info("\n%s", collect_results(hall_of_fame))


def write_hall(filename, hall_of_fame):
    """
    Writes hall of fame out to a file.

    Args:
        filename (str): Filename to write results to
        hall_of_fame (dict): Hall of fame of individuals
    """
    with open(filename, "w") as fd:
        fd.write(collect_results(hall_of_fame))


def eval_only(logger, requested, ga_evaluator, runs=1):
    """
    Parses a string representation of a given strategy and runs it
    through the evaluator.

    Args:
        logger (:obj:`logging.Logger`): A logger to log with
        requested (str): String representation of requested strategy or filename
            of strategies
        ga_evaluator (:obj:`evaluator.Evaluator`): An evaluator to evaluate with
        runs (int): Number of times each strategy should be evaluated

    Returns:
        float: Success rate of tested strategies
    """
    # The user can specify a file that contains strategies - check first if that is the case
    if os.path.isfile(requested):
        with open(requested, "r") as fd:
            requested_strategies = fd.readlines()
        if not requested_strategies:
            logger.error("No strategies found in %s", requested)
            return None
    else:
        requested_strategies = [requested]
    # We want to override the client's default strategy retry logic to ensure
    # we test to the number of runs requested
    ga_evaluator.runs = 1
    population = []

    for requested in requested_strategies:
        for i in range(runs):
            ind = actions.utils.parse(requested, logger)
            population.append(ind)
        logging.info("Computing fitness for: %s", str(ind))
        logging.info("\n%s", ind.pretty_print())

    fits = []
    success = 0
    # Once the population has been parsed and built, test it
    fitness_function(logger, population, ga_evaluator)
    for strat in population:
        fits.append(strat.fitness)
    i = 0
    logger.info(fits)
    for fitness in fits:
        if fitness > 0:
            success += 1
            logger.info("Trial %d: success! (fitness = %d)", i, fitness)
        else:
            logger.info("Trial %d: failure! (fitness = %d)", i, fitness)
        i += 1
    if fits:
        logger.info("Overall %d/%d = %d%%", success, i, int((float(success)/float(i)) * 100))
    logger.info("Exiting eval-only.")
    return float(success)/float(i)


def restrict_headers(logger, protos, filter_fields, disabled_fields):
    """
    Restricts which protocols/fields can be accessed by the algorithm.

    Args:
        logger (:obj:`logging.Logger`): A logger to log with
        protos (str): Comma separated string of protocols that are allowed
        filter_fields (str): Comma separated string of fields to allow
        disabled_fields (str): Comma separated string of fields to disable
    """
    # Retrieve flag and protocol filters, and validate them
    protos = protos.upper().split(",")
    if filter_fields:
        filter_fields = filter_fields.lower().split(",")
    if disabled_fields:
        disabled_fields = disabled_fields.split(",")

    layers.packet.Packet.restrict_fields(logger, protos, filter_fields, disabled_fields)


def driver(cmd):
    """
    Main workflow driver for the solver. Parses flags and input data, and initiates solving.

    Args:
        cmd (list): sys.argv or a list of arguments

    Returns:
        dict: Hall of fame of individuals
    """
    # Parse the given arguments
    args = get_args(cmd)

    logger = setup_logger(args.log)

    lock_file_path = "/lock_file.txt"
    if not args.no_lock_file and os.path.exists(lock_file_path):
        logger.info("Lock file \"%s\" already exists.", lock_file_path)
        return None

    try:
        if not args.no_lock_file:
            # Create lock file to prevent interference between multiple runs
            open(lock_file_path, "w+")

        # Log the command run
        logger.debug("Launching strategy evolution: %s", " ".join(cmd))
        logger.info("Logging results to %s", logger.ga_log_dir)

        if args.no_eval and args.eval_only:
            print("ERROR: Cannot --eval-only with --no-eval.")
            return None

        requested_strategy = args.eval_only

        # Define an evaluator for this session
        ga_evaluator = None
        if not args.no_eval:
            cmd += ["--output-directory", actions.utils.RUN_DIRECTORY]
            ga_evaluator = evaluator.Evaluator(cmd, logger)

        # Check if the user only wanted to evaluate a single given strategy
        # If so, evaluate it, and exit
        if requested_strategy or requested_strategy == "":
            # Disable evaluator empty strategy skipping
            ga_evaluator.skip_empty = False
            eval_only(logger, requested_strategy, ga_evaluator, runs=args.runs)
            return None

        restrict_headers(logger, args.protos, args.fields, args.disable_fields)

        actions.trigger.GAS_ENABLED = (not args.no_gas)
        if args.fix_trigger:
            actions.trigger.FIXED_TRIGGER = actions.trigger.Trigger.parse(args.fix_trigger)

        requested_seed = args.seed
        if requested_seed or requested_seed == "":
            try:
                requested_seed = actions.utils.parse(args.seed, logger)
            except (TypeError, AssertionError, actions.tree.ActionTreeParseError):
                logger.error("Failed to parse given strategy: %s", requested_seed)
                raise

        # Record all of the options supplied by the user to pass to the GA
        options = {}
        options["no_reject_empty"] = not args.no_reject_empty
        options["population_size"] = args.population
        options["out-trees"] = args.out_trees
        options["in-trees"] = args.in_trees
        options["in-actions"] = args.in_actions
        options["out-actions"] = args.out_actions
        options["force_cleanup"] = args.force_cleanup
        options["num_generations"] = args.generations
        options["seed"] = args.seed
        options["elite_clones"] = args.elite_clones
        options["allowed_retries"] = args.allowed_retries
        options["mutation_pb"] = args.mutation_pb
        options["crossover_pb"] = args.crossover_pb
        options["no-canary"] = args.no_canary
        options["load_from"] = args.load_from

        disable_action = []
        if args.disable_action:
            disable_action = args.disable_action.split(",")
        options["disable_action"] = disable_action

        logger.info("Initializing %d strategies with %d input-action trees and %d output-action trees of input size %d and output size %d for evolution over %d generations.",
                    args.population, args.in_trees, args.out_trees, args.in_actions, args.out_actions, args.generations)

        hall_of_fame = {}
        try:
            # Kick off the main genetic driver
            hall_of_fame = genetic_solve(logger, options, ga_evaluator)
        except KeyboardInterrupt:
            logger.info("User shutdown requested.")
        if ga_evaluator:
            ga_evaluator.shutdown()

        if hall_of_fame and not args.no_print_hall:
            # Print the final results
            print_results(hall_of_fame, logger)

        # Teardown the evaluator if needed
        if ga_evaluator:
            ga_evaluator.shutdown()
    finally:
        # Remove lock file
        if os.path.exists(lock_file_path):
            os.remove(lock_file_path)
    return hall_of_fame


if __name__ == "__main__":
    driver(sys.argv[1:])
