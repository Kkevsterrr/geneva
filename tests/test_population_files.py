import sys
import pytest
sys.path.append("..") # Include the root of the project
import evolve
import os
import actions.utils
import layers.layer

# Test Files Directory Setup
test_files_directory = os.path.join("test_files")
if not os.path.exists(test_files_directory):
    os.mkdir(test_files_directory)


def check_one_file(logger, evolve_options, filename, population):
    """
    Checks if the population in the file matches the population specified
    """

    # Number of lines in the file should match the population size
    lines = sum(1 for line in open(filename))
    assert lines == len(population)

    # Loading the contents in the generation file should be equal to each random strategy
    file_strategies = evolve.load_generation(logger, filename)
    # Write the output of the loaded generation file for debugging purposes in case the test fails
    output_file = filename + ".output"
    evolve.write_generation(output_file, file_strategies)

    for index, strategy in enumerate(file_strategies):
        assert str(strategy) == str(population[index])

    # Initializing the population without the "load_from" option should not be equal in total
    random_strategies = evolve.initialize_population(logger, evolve_options, None)
    file_strategies_str, population_str = '', ''

    for strategy in random_strategies:
        file_strategies_str += str(strategy)

    for strategy in population:
        population_str += str(strategy)

    assert file_strategies_str != population_str

    # Initializing the population with the "load_from" option should be equal for each strategy
    evolve_options["load_from"] = filename
    file_strategies = evolve.initialize_population(logger, evolve_options, None)
    for index, individual in enumerate(file_strategies):
        assert str(individual) == str(population[index])


def test_save_and_load_generation(logger):
    """
    Generate random strategies (total number = generations * options["population_size"]),
    writes the population to a file and then checks the file contents to see if it
    matches the correct population when it is parsed back into the program
    """

    generations = 2

    options = {}
    options["population_size"] = 10000
    options["in-trees"] = 0
    options["out-trees"] = 1
    options["in-actions"] = 0
    options["out-actions"] = 3
    options["library"] = False
    options["seed"] = None

    for generation_index in range(generations):
        population = []
        population_str = ''

        # Generate random strategies to initialize the population
        for i in range(options["population_size"]):
            p = evolve.generate_strategy(logger, options["in-trees"], options["out-trees"], options["in-actions"],
                                         options["out-actions"],
                                         options["seed"], environment_id=None)
            actions.utils.parse(str(p), logger)
            population.append(p)
            if i == options["population_size"] - 1:
                population_str += str(p)
            else:
                population_str += str(p) + "\n"

        # Write the generation file
        filename = os.path.join(test_files_directory, "generation" + str(generation_index))
        evolve.write_generation(filename, population)

        check_one_file(logger, options, filename, population)


def test_evolve_load_generation(logger):
    """
    Generate random strategies (total number = generations * options["population_size"]),
    writes the population to a file and then checks the file contents to see if it
    matches the correct population when it is parsed back into the program
    """

    generations = 2
    layers.packet.Packet.reset_restrictions()

    options = {}
    options["population_size"] = 2
    options["in-trees"] = 0
    options["out-trees"] = 1
    options["in-actions"] = 0
    options["out-actions"] = 3
    options["library"] = False
    options["seed"] = None

    for generation_index in range(generations):
        population = []
        population_str = ''

        # Generate random strategies to initialize the population
        for i in range(options["population_size"]):
            p = evolve.generate_strategy(logger, options["in-trees"], options["out-trees"], options["in-actions"],
                                         options["out-actions"],
                                         options["seed"], environment_id=None)
            print(str(p))
            actions.utils.parse(str(p), logger)
            population.append(p)
            if i == options["population_size"] - 1:
                population_str += str(p)
            else:
                population_str += str(p) + "\n"

        # Write the generation file
        filename = os.path.join(test_files_directory, "generation" + str(generation_index))
        evolve.write_generation(filename, population)

    cmd = [
        "--population", "3",
        "--generations", "1",
        "--test-type", "http",
        "--load-from", filename,
        "--port", "80",
        "--protos", "ip,udp,tcp,dns,dnsqr",
        "--censor", "censor2",
        "--log", "debug",
        "--no-skip-empty",
    ]
    print(evolve.driver(cmd))


@pytest.mark.skip
def test_one_file():
    """
    Used for manual testing. Loads a specified file in the
    test_files_directory and checks it
    """
    # Set filename here
    filename = os.path.join(test_files_directory, "generation0")

    options = {}
    options["population_size"] = 5
    options["in-trees"] = 0
    options["out-trees"] = 1
    options["in-actions"] = 0
    options["out-actions"] = 3
    options["library"] = False
    options["seed"] = None

    population = evolve.load_generation(filename)

    check_one_file(options, filename, population)
