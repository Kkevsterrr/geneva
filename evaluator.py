"""
The Evaluator is charged with evaluating a given strategy and assigning a numerical fitness metric to it.
"""
import argparse
import copy
import logging
import multiprocessing
import os
import random
import socket
import subprocess
import sys
import threading
import time
import re
import warnings

import requests
import urllib3

import actions.utils
import censors.censor_driver


# Suppress unfixed Paramiko warnings (see Paramiko issue #1386)
warnings.filterwarnings(action='ignore',module='.*paramiko.*')

# Placeholder for a docker import (see below why we cannot import docker here)
docker = None
BASEPATH = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = BASEPATH


class Evaluator():
    def __init__(self, command, logger):
        """
        Initialize the global evaluator for this evolution.

        Args:
            command (list): sys.argv or list of arguments
            logger (:obj:`logging.Logger`): logger passed in from the main driver to log from
        """
        self.args = get_args(command)
        self.test_plugin = self.args["test_type"]
        assert self.test_plugin, "Cannot import an empty plugin"

        self.public_ip = self.args.get("public_ip", "")

        self.external_client = self.args["external_client"]
        self.censor = self.args.get("censor")
        # If there is no external client defined and no internal test setup, default --external-server to True
        if not self.external_client and not self.censor:
            self.args["external_server"] = True

        self.external_server = self.args["external_server"]

        # If there is an external client connecting to us, override the server with our public ip
        if not self.external_server and self.external_client:
            assert self.args.get("public_ip", ""), "Cannot use an external client to this server without specifying the public IP."
            self.public_ip = self.args.get("public_ip", "")
            worker = actions.utils.get_worker(self.public_ip, logger)
            if worker:
                self.public_ip = worker["ip"]
            self.args.update({'server': self.public_ip})
            command += ["--server", self.public_ip]

        self.run_canary_phase = True

        self.client_args = copy.deepcopy(self.args)
        self.server_args = copy.deepcopy(self.args)

        self.client_cls = None
        self.server_cls = None
        self.plugin = None

        self.override_evaluation = False

        # Plugin may optionally override the strategy evaluation for a single individual or the entire evaluation
        try:
            _, plugin_cls = actions.utils.import_plugin(self.test_plugin, "plugin")
            parsed_args = plugin_cls.get_args(command)
            self.args.update({k:v for k,v in parsed_args.items() if v or (not v and k not in self.args)})
            self.plugin = plugin_cls(self.args)
            # Disable the canary phase if the plugin will override the default evaluation logic
            self.run_canary_phase = not self.plugin.override_evaluation
            self.override_evaluation = self.plugin.override_evaluation
        except ImportError:
            pass

        self.client_cls = collect_plugin(self.test_plugin, "client", command, self.args, self.client_args)
        self.server_cls = collect_plugin(self.test_plugin, "server", command, self.args, self.server_args)

        self.workers = self.args["workers"]
        self.stop = False
        self.skip_empty = not self.args["no_skip_empty"]
        self.output_directory = self.args["output_directory"]

        self.routing_ip = self.args.get("routing_ip", None)
        self.runs = self.args.get("runs", 1)
        self.fitness_by = self.args.get("fitness_by", "avg")

        self.forwarder = {}
        # If NAT options were specified to train as a middle box, set up the engine's
        # NAT configuration
        self.act_as_middlebox = self.args.get("act_as_middlebox")
        if self.act_as_middlebox:
            assert self.args.get("forward_ip")
            assert self.args.get("sender_ip")
            assert self.args.get("routing_ip")
            self.forwarder["forward_ip"] = self.args["forward_ip"]
            self.forwarder["sender_ip"] = self.args["sender_ip"]
            self.forwarder["routing_ip"] = self.args["routing_ip"]

        # Legacy environments storage
        self.environments = []
        if not os.path.exists(self.output_directory):
            os.mkdir(self.output_directory)

        # Only enable docker if we're going to use an internal censor
        self.use_docker = False
        if self.args["censor"]:
            import docker
            self.use_docker = True
            self.docker_client = docker.from_env()
            self.apiclient = docker.APIClient()

        self.logger = logger

    def evaluate(self, ind_list):
        """
        Perform the overall fitness evaluation driving.

        Args:
            ind_list (list): list of individuals to evaluate

        Returns:
            list: Population list after evaluation
        """
        # Setup environment ids for each individual
        self.assign_ids(ind_list)

        # If the plugin has overridden default evaluation, call that here
        if self.override_evaluation:
            self.logger.debug("Beginning evaluation in plugin")
            return self.plugin.evaluate(self.args, self, ind_list, self.logger)

        if self.workers > 1 and self.use_docker:
            # Chunk the population and test sites into smaller lists to hand to each worker
            split = [ind_list[i::self.workers] for i in range(0, self.workers)]

            procs = []
            # Create workers
            for i in range(0, len(split)):
                if not split[i]:
                    continue
                if self.use_docker:
                    try:
                        # Due to limitations in docker-py, it is not safe to build the containers in a multiprocessed
                        # setting. To handle this, build the environments ahead of time, and pass them to the workers to use.
                        environment = self.create_test_environment(i)
                    except (docker.errors.APIError, requests.exceptions.ConnectionError, urllib3.exceptions.ProtocolError):
                        self.logger.exception("Failed to create evaluator environment - is docker running?")
                        return

                proc = multiprocessing.Process(target=self.worker, args=(split[i], str(i), environment))
                proc.start()
                procs.append(proc)

            try:
                # Join all the processes
                for proc in procs:
                    proc.join()
            except KeyboardInterrupt:
                self.shutdown()
        else:
            environment = {}
            if self.use_docker:
                try:
                    environment = self.create_test_environment("main")
                except (docker.errors.APIError, requests.exceptions.ConnectionError, urllib3.exceptions.ProtocolError):
                    self.logger.exception("Failed to create evaluator environment - is docker running?")
                    return

            self.worker(ind_list, "main", environment)

        for ind in ind_list:
            self.read_fitness(ind)
        self.terminate_docker()

        return ind_list

    def run_test(self, environment, ind):
        """
        Conducts a test of a given individual in the environment.

        Args:
            environment (dict): Dictionary of environment variables
            ind (:obj:`actions.strategy.Strategy`): A strategy object to test with

        Returns:
            tuple: (ind.environment_id, ind.fitness) environment ID of strategy and fitness
        """
        # If skip_empty is enabled, this is not the canary, and the individual is empty,
        # skip it
        if len(ind) == 0 and ind.environment_id != "canary" and self.skip_empty:
            self.logger.info("[skipped] Fitness %d: %s" % (-1000, str(ind)))
            ind.fitness = -1000
            return "skipped", -1000

        fitnesses = []

        # Run the strategy multiple times if requested
        for run in range(0, self.runs):
            self.logger.debug("Launching %s plugin (run %d) for %s" % (self.test_plugin, run + 1, str(ind)))

            environment["id"] = ind.environment_id
            self.client_args.update({"environment_id": ind.environment_id})
            self.server_args.update({"environment_id": ind.environment_id})

            if not self.args["server_side"]:
                self.client_args.update({"strategy" : str(ind)})
                self.server_args.update({"no_engine" : True})
            else:
                self.server_args.update({"strategy" : str(ind)})
                self.client_args.update({"no_engine" : True})

            # If we're using an internal censor, make sure the client is pointed at the server
            if self.args["censor"]:
                self.client_args.update({"server": environment["server"]["ip"]})
                self.client_args.update({"wait_for_censor": True})
                self.server_args.update({"wait_for_shutdown": True})
                self.update_ports(environment)

            try:
                # If the plugin has overridden the below logic, run that plugin's version directly
                if self.plugin:
                    self.logger.debug("Running standalone plugin.")
                    self.args.update({"strategy": str(ind)})
                    self.plugin.start(self.args, self, environment, ind, self.logger)
                    self.read_fitness(ind)
                else:
                    self.logger.debug("Launching client and server directly.")
                    # If we're given a server to start, start it now
                    if self.server_cls and not self.external_server and not self.act_as_middlebox:
                        server = self.start_server(self.server_args, environment, self.logger)

                    fitness = self.run_client(self.client_args, environment, self.logger)

                    if self.server_cls and not self.external_server and not self.act_as_middlebox:
                        self.stop_server(environment, server)

                    self.read_fitness(ind)

                    # If the engine ran on the server side, ask that it punish fitness
                    if self.args["server_side"]:
                        ind.fitness = server.punish_fitness(ind.fitness, self.logger)
                        actions.utils.write_fitness(ind.fitness, self.output_directory, environment["id"])
            except actions.utils.SkipStrategyException as exc:
                self.logger.debug("Strategy evaluation ending.")
                ind.fitness = exc.fitness
                fitnesses.append(ind.fitness)
                break

            fitnesses.append(ind.fitness)

            if self.runs > 1:
                self.logger.debug("\t(%d/%d) Fitness %s: %s" % (run + 1, self.runs, str(ind.fitness), str(ind)))

        self.logger.debug("Storing fitness of %s by: %s" % (fitnesses, self.fitness_by))
        if self.fitness_by == "min":
            ind.fitness = min(fitnesses)
        elif self.fitness_by == "max":
            ind.fitness = max(fitnesses)
        elif self.fitness_by == "avg":
            ind.fitness = round(sum(fitnesses)/len(fitnesses), 2)
        actions.utils.write_fitness(ind.fitness, self.output_directory, environment["id"])

        # Log the fitness
        self.logger.info("[%s] Fitness %s: %s" % (ind.environment_id, str(ind.fitness), str(ind)))

        return ind.environment_id, ind.fitness

    def run_client(self, args, environment, logger):
        """
        Runs the plugin client given the current configuration

        Args:
            args (dict): Dictionary of arguments
            environment (dict): Dictionary describing environment configuration for this evaluation
            logger (:obj:`logging.Logger`): A logger to log with

        Returns:
            float: Fitness of individual
        """
        fitness = None
        if environment.get("remote"):
            fitness = self.run_remote_client(args, environment, logger)
        elif environment.get("docker"):
            self.run_docker_client(args, environment, logger)
        else:
            self.run_local_client(args, environment, logger)

        fitpath = os.path.join(BASEPATH, self.output_directory, actions.utils.FLAGFOLDER, environment["id"]) + ".fitness"
        # Do not overwrite the fitness if it already exists
        if not os.path.exists(fitpath):
            actions.utils.write_fitness(fitness, self.output_directory, environment["id"])
        return fitness

    def run_docker_client(self, args, environment, logger):
        """
        Runs client within the docker container. Does not return fitness; instead
        fitness is written via the flags directory and read back in later.

        Args:
            args (dict): Dictionary of arguments
            environment (dict): Dictionary describing environment configuration for this evaluation
            logger (:obj:`logging.Logger`): A logger to log with
        """
        command = ["docker", "exec", "--privileged", environment["client"]["container"].name, "python", "code/plugins/plugin_client.py", "--server", environment["server"]["ip"]]
        base_cmd = actions.utils.build_command(args)
        command += base_cmd
        self.exec_cmd(command)

    def update_ports(self, environment):
        """
        Checks that the chosen port is open inside the docker container - if not, it chooses a new port.

        Args:
            environment (dict): Dictionary describing docker environment
        """
        command = ["docker", "exec", "--privileged", environment["server"]["container"].name, "netstat", "-ano"]
        output = self.exec_cmd_output(command)
        requested_port = self.args.get("port")
        self.logger.debug("Testing if port %s is open in the docker container" % requested_port)
        while (":%s" % requested_port) in output:
            self.logger.warn("Port %s is in use, choosing a new port" % requested_port)
            requested_port = random.randint(1000, 65000)
            output = self.exec_cmd_output(command)
        self.logger.debug("Using port %s" % requested_port)
        self.args.update({"port": requested_port})
        self.client_args.update({"port": requested_port})
        self.server_args.update({"port": requested_port})

    def run_remote_client(self, args, environment, logger):
        """
        Runs client remotely over SSH, using the given SSH channel

        Args:
            args (dict): Dictionary of arguments
            environment (dict): Dictionary describing environment configuration for this evaluation
            logger (:obj:`logging.Logger`): A logger to log with

        Returns:
            float: Fitness of individual
        """
        worker = environment["worker"]
        remote = environment["remote"]
        command = []
        if worker["username"] != "root":
            command = ["sudo"]
        command += [worker["python"], os.path.join(worker["geneva_path"], "plugins/plugin_client.py")]
        base_cmd = actions.utils.build_command(args)
        command += base_cmd
        command = " ".join(command)

        self.remote_exec_cmd(remote, command, logger, timeout=20)

        # Get the logs from the run
        self.get_log(remote, worker, "%s.client.log" % environment["id"], logger)
        if not args["server_side"]:
            self.get_log(remote, worker, "%s.engine.log" % environment["id"], logger)

        # Get the individual's fitness
        command = 'cat %s/%s/%s/%s.fitness' % (worker["geneva_path"], self.output_directory, actions.utils.FLAGFOLDER, environment["id"])
        remote_fitness, error_lines = self.remote_exec_cmd(remote, command, logger)
        fitness = -1000
        try:
            fitness = int(remote_fitness[0])
        except Exception:
            logger.exception("Failed to parse remote fitness.")
            return None

        return fitness

    def remote_exec_cmd(self, remote, command, logger, timeout=15, verbose=True):
        """
        Given a remote SSH session, executes a string command. Blocks until
        command completes, and returns the stdout and stderr. If the SSH
        connection is broken, it will try again.

        Args:
            remote: Paramiko SSH channel to execute commands over
            command (str): Command to execute
            logger (:obj:`logging.Logger`): A logger to log with
            timeout (int, optional): Timeout for the command
            verbose (bool, optional): Whether the output should be printed

        Returns:
            tuple: (stdout, stderr) of command, each is a list
        """
        i, max_tries = 0, 3
        lines = []
        error_lines = []
        stdin_, stdout_, stderr_ = None, None, None
        while i < max_tries:
            try:
                if verbose:
                    logger.debug(command)
                stdin_, stdout_, stderr_ = remote.exec_command(command, timeout=timeout)
                # Block until the client finishes
                stdout_.channel.recv_exit_status()
                error_lines = stderr_.readlines()
                lines = stdout_.readlines()
                break
            # We would like to catch paramiko.SSHException here, but because of issues with importing paramiko
            # at the top of the file in the main namespace, we catch Exception instead as a broader exception.
            except Exception:
                logger.error("Failed to execute \"%s\" on remote host. Re-creating SSH tunnel." % command)
                # Note that at this point, our remote object still has a valid channel as far as paramiko is
                # concerned, but the channel is no longer responding. If we tried to do remote.close() here,
                # it would hang our process. Instead, we'll set up a new remote channel, and let Python's garbage
                # collection handle destroying the original remote object for us.
                try:
                    remote = self.setup_remote()
                except Exception:
                    logger.error("Failed to re-connect remote - trying again.")
                i += 1

        if verbose:
            for line in error_lines:
                logger.debug("ERROR: %s", line.strip())
        # Close the channels
        if stdin_:
            stdin_.close()
        if stdout_:
            stdout_.close()
        if stderr_:
            stderr_.close()
        return lines, error_lines

    def get_log(self, remote, worker, log_name, logger):
        """
        Retrieves a log from the remote server and writes it to disk.

        Args:
            remote: A Paramiko SSH channel to execute over
            worker (dict): Dictionary describing external client worker
            log_name (str): Log name to retrieve
            logger (:obj:`logging.Logger`): A logger to log with
        """
        # Get the client.log
        log_path = os.path.join(self.output_directory, "logs", log_name)
        command = "cat %s" % os.path.join(worker["geneva_path"], log_path)
        client_log, error_lines = self.remote_exec_cmd(remote, command, logger, verbose=False)
        # If something goes wrong, we don't necessarily want to dump the entire client_log to the screen
        # a second time, so just disable verbosity and display the stderr.
        for line in error_lines:
            logger.error(line.strip())

        # Write the client log out to disk
        with open(log_path, "w") as fd:
            for line in client_log:
                fd.write(line)

    def run_local_client(self, args, environment, logger):
        """
        Runs client locally. Does not return fitness.

        Args:
            args (dict): Dictionary of arguments
            environment (dict): Dictionary describing environment configuration for this evaluation
            logger (:obj:`logging.Logger`): A logger to log with
        """
        # Launch the plugin client
        command = [sys.executable, "plugins/plugin_client.py", "--plugin", self.client_cls.name]
        base_cmd = actions.utils.build_command(args)
        command += base_cmd
        # Replace strings of empty strings "''" with empty strings "", as subprocess will handle this correctly
        command = [x if x != "''" else "" for x in command]
        logger.debug(" ".join(command))
        self.exec_cmd(command)

    def exec_cmd(self, command, timeout=60):
        """
        Runs a subprocess command at the correct log level.

        Args:
            command (list): Command to execute.
            timeout (int, optional): Timeout for execution
        """
        self.logger.debug(" ".join(command))
        try:
            if actions.utils.get_console_log_level() == "debug":
                subprocess.check_call(command, timeout=60)
            else:
                subprocess.check_call(command, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=60)
        except subprocess.CalledProcessError as exc:
            # Code 137 is for SIGKILL, which is how docker containers are shutdown by the evaluator.
            # Ignore these exceptions, raise all others
            if exc.returncode != 137:
                raise

    def exec_cmd_output(self, command, timeout=60):
        """
        Runs a subprocess command at the correct log level. This is a separate method from the above exec_cmd,
        since that is used to stream output to the screen (so check_output is not appropriate).

        Args:
            command (list): Command to execute.
            timeout (int, optional): Timeout for execution

        Returns:
            str: Output of command
        """
        self.logger.debug(" ".join(command))
        output = ""
        try:
            output = subprocess.check_output(command, timeout=60, stderr=subprocess.PIPE).decode('utf-8', 'ignore')
            if actions.utils.get_console_log_level() == "debug":
                self.logger.debug(output)
        except subprocess.CalledProcessError as exc:
            # Code 137 is for SIGKILL, which is how docker containers are shutdown by the evaluator.
            # Ignore these exceptions, raise all others
            if exc.returncode != 137:
                raise
        return output

    def start_server(self, args, environment, logger):
        """
        Launches the server.

        Args:
            args (dict): Dictionary of arguments
            environment (dict): Dictionary describing environment configuration for this evaluation
            logger (:obj:`logging.Logger`): A logger to log with

        Return:
            float: fitness of individual (if one is provided)
        """
        if environment.get("docker"):
            logger.debug("Evaluator: running server inside docker")
            return self.run_docker_server(args, environment, logger)
        else:
            logger.debug("Evaluator: running server")
            return self.run_local_server(args, environment, logger)

    def run_docker_server(self, args, environment, logger):
        """
        Runs server and censor in their respective docker containers.

        Args:
            args (dict): Dictionary of arguments
            environment (dict): Dictionary describing environment configuration for this evaluation
            logger (:obj:`logging.Logger`): A logger to log with
        """
        command = ["docker", "exec", "--privileged", environment["server"]["container"].name, "python", "code/plugins/plugin_server.py", "--test-type", self.server_cls.name]
        base_cmd = actions.utils.build_command(args)
        command += base_cmd
        # Replace strings of empty strings "''" with empty strings "", as subprocess will handle this correctly
        command = [x if x != "''" else "" for x in command]

        port = args.get("port")
        queue_num = random.randint(1, 1000)
        environment["port"] = port
        environment["queue_num"] = queue_num
        server_thread = threading.Thread(target=self.exec_cmd, args=(command, ))
        censor_thread = threading.Thread(target=self.start_censor, args=(environment, environment["id"]))
        censor_thread.start()
        server_thread.start()
        max_wait = 30
        count = 0
        flag_file = os.path.join(args["output_directory"], "flags", "%s.server_ready" % args["environment_id"])

        while count < max_wait:
            if os.path.exists(flag_file):
                break
            if count % 15 == 0:
                logger.debug("Evaluator waiting for confirmation of server startup")
            count += 1
            time.sleep(0.5)
        else:
            logger.warn("Evaluator: Server did not startup within window")
            return
        logger.debug("Evaluator: Server ready.")

    def stop_server(self, environment, server):
        """
        Stops server.

        Args:
            environment (dict): Environment dictionary
            server (:obj:`plugins.plugin_server.ServerPlugin`): A plugin server to stop
        """
        # If the server is running inside a docker container, we don't have access to it directly
        # to shut it down. Instead, write a shutdown flag to instruct it to shut down.
        self.logger.debug("Evaluator shutting down server.")
        if environment.get("docker"):
            flag_file = os.path.join(self.args["output_directory"], "flags", "%s.server_shutdown" % self.server_args["environment_id"])
            # Touch shutdown file to instruct the server to shutdown
            open(flag_file, 'a').close()
            self.stop_censor(environment)
        else:
            # Shut down the server
            server.stop()
            # Shut down the server's logger, now that we are done with it
            actions.utils.close_logger(environment["server_logger"])

    def run_local_server(self, args, environment, logger):
        """
        Runs local server.

        Args:
            args (dict): Dictionary of arguments
            environment (dict): Dictionary describing environment configuration for this evaluation
            logger (:obj:`logging.Logger`): A logger to log with
        """
        server = self.server_cls(args)
        logger.debug("Starting local server with args: %s" % str(args))
        server_logger = actions.utils.get_logger(PROJECT_ROOT, args["output_directory"], "server", "server", environment["id"], log_level=actions.utils.get_console_log_level())
        environment["server_logger"] = server_logger
        args.update({"test_type": self.server_cls.name})
        if not args.get("server_side"):
            args.update({"no_engine" : True})
        server.start(args, server_logger)
        return server

    def canary_phase(self, canary):
        """
        Learning phase runs the client against the censor to collect packets.

        Args:
            canary (:obj:`actions.strategy.Strategy`): A (usually empty) strategy object to evaluate

        Returns:
            str: canary id used ("canary")
        """
        if not self.run_canary_phase:
            return None

        self.logger.info("Starting collection phase")
        environment = {}
        canary.environment_id = "canary"
        if self.use_docker:
            try:
                environment = self.create_test_environment("canary")
            except (docker.errors.APIError, requests.exceptions.ConnectionError, urllib3.exceptions.ProtocolError):
                self.logger.error("Failed to create evaluator environment - is docker running?")
                return None

        self.worker([canary], canary.environment_id, environment)

        self.logger.info("Collected packets under %s" % canary)
        return "canary"

    def get_ip(self):
        """
        Gets IP of evaluator computer.

        Returns:
            str: Public IP provided
        """
        if self.public_ip:
            return self.public_ip
        return None

    def create_test_environment(self, worker_id):
        """
        Creates a test environment in docker.

        Args:
            worker_id (int): Worker ID of this worker

        Returns:
            dict: Environment dictionary to use
        """
        self.logger.debug("Initializing docker environment.")

        # We can't have an environment with an intenral test server and no censor
        # with the current set up. To be addressed later to allow for no censor testing
        assert not (not self.censor and not self.external_server), "Can't create internal server w/o censor"
        assert not (self.censor and self.external_server), "Can't create a censor without an internal training server"

        # Create a dict to hold the environment we're about to create
        environment = {}

        # Create the client container
        environment["client"] = self.initialize_base_container("client_%s" % worker_id)
        environment["client"]["ip"] = self.parse_ip(environment["client"]["container"], "eth0")

        # If a training censor is requested, create a censor container
        if self.censor:
            environment["censor"] = self.initialize_base_container("censor_%s" % worker_id)
            environment["server"] = self.initialize_base_container("server_%s" % worker_id)
            # Set up the routing
            environment["server"]["ip"] = self.parse_ip(environment["server"]["container"], "eth0")
            environment["censor"]["ip"] = self.parse_ip(environment["censor"]["container"], "eth0")
            self._add_route(environment["server"]["container"], environment["censor"]["ip"])
            self._add_route(environment["client"]["container"], environment["censor"]["ip"])

            # Calculate the network base ("172.17.0.0")
            network_base = ".".join(environment["server"]["ip"].split(".")[:2]) + ".0.0"

            # Delete all other routes for the server and client to force communication through the censor
            environment["server"]["container"].exec_run(["route", "del", "-net", network_base, "gw", "0.0.0.0", "netmask", "255.255.0.0", "dev", "eth0"], privileged=True)
            environment["client"]["container"].exec_run(["route", "del", "-net", network_base, "gw", "0.0.0.0", "netmask", "255.255.0.0", "dev", "eth0"], privileged=True)

            # Set up NAT on the censor
            environment["censor"]["container"].exec_run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE"], privileged=True)

        self.environments.append(environment)
        # Flag that this environment is a docker environment
        environment["docker"] = True
        # Return the configured environment for use
        return environment

    def _add_route(self, container, via):
        """
        Helper method to take down an interface on a container

        Args:
            container: Docker container object to execute within
            via (str): IP address to route through
        """
        exit_code, _output = container.exec_run(["ip", "route", "del", "default"], privileged=True)
        exit_code, _output = container.exec_run(["ip", "route", "add", "default", "via", via], privileged=True)
        return exit_code

    def parse_ip(self, container, iface):
        """
        Helper method to parse an IP address from ifconfig.

        Args:
            container: Docker container object to execute within
            iface (str): Interface to parse from

        Returns:
            str: IP address
        """
        _exit_code, output = container.exec_run(["ifconfig", iface], privileged=True)
        ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', output.decode("utf-8"))[0]
        return ip

    def setup_remote(self):
        """
        Opens an SSH tunnel to the remote client worker.
        """
        # Import paramiko here instead of at the top of the file. This is done intentionally. When
        # paramiko is imported, pynacl is loaded, which polls /dev/random for entropy to setup crypto
        # keys. However, if the evaluator is run on a relatively blank VM (or AWS instance) with little
        # network traffic before it starts (as will often be the case), there may be insufficient entropy
        # available in the system. This will cause pynacl to block on entropy, and since the only thing
        # running on the system is now blocking, it is liable to block indefinitely. Instead, the import
        # is performed here so that the system interaction of running the evaluator this far collects
        # enough entropy to not block paramiko. The pynacl team is aware of this issue: see issue #503
        # (https://github.com/pyca/pynacl/issues/503) and #327 (https://github.com/pyca/pynacl/issues/327)
        import paramiko
        paramiko_logger = paramiko.util.logging.getLogger()
        paramiko_logger.setLevel(logging.WARN)
        worker = actions.utils.get_worker(self.external_client, self.logger)

        if self.use_docker:
            worker["ip"] = "0.0.0.0"

        # Pull the destination to connect to this worker. Preference hostnames over IP addresses.
        destination = worker["hostname"]
        if not destination:
            destination = worker["ip"]

        self.logger.debug("Connecting to worker %s@%s" % (worker["username"], destination))
        remote = paramiko.SSHClient()
        remote.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        max_tries = 5
        i = 0
        while i < max_tries:
            try:
                if "keyfile" in worker:
                    k = paramiko.RSAKey.from_private_key_file(worker["keyfile"])
                    remote.connect(destination, username=worker["username"], pkey=k, port=worker["port"], timeout=60)
                else:
                    remote.connect(destination, username=worker["username"], password=worker["password"], port=worker["port"], timeout=60)
                break
            except socket.timeout:
                self.logger.error("Could not connect to worker %s" % destination)
                i += 1
        return remote

    def worker(self, ind_list, worker_id, environment):
        """
        Perform the actual fitness evaluation as a multithreaded worker. The
        worker pops off an individual from the list and evaluates it.

        Args:
            ind_list (list): List of strategy objects to evaluate
            worker_id (int): ID of this worker
            environment (dict): Environment dictionary
        """
        environment["remote"] = None

        if self.external_client:
            environment["remote"] = self.setup_remote()
            environment["worker"] = actions.utils.get_worker(self.external_client, self.logger)

        for ind in ind_list:
            if self.stop:
                break

            # Run a test
            eid, fitness = self.run_test(environment, ind)

            if not fitness:
                fitness = -1000

            # Dump logs if requested
            if fitness < 0 and self.args.get("log_on_fail"):
                self.dump_logs(eid)
            elif fitness > 0 and self.args.get("log_on_success"):
                self.dump_logs(eid)

        # Clean up the test environment
        self.shutdown_environment(environment)

    def assign_ids(self, ind_list):
        """
        Assigns random environment ids to each individual to be evaluated.

        Args:
            ind_list (list): List of individuals to assign random IDs to
        """
        for ind in ind_list:
            ind.environment_id = actions.utils.get_id()
            ind.fitness = None

    def dump_logs(self, environment_id):
        """
        Dumps client, engine, server, and censor logs, to be called on test failure
        at ERROR level.

        Args:
            environment_id (str): Environment ID of a strategy to dump
        """
        log_files = ["client.log", "engine.log", "censor.log", "server.log"]
        for log_file in log_files:
            log = ""
            log_path = os.path.join(BASEPATH,
                                    self.output_directory,
                                    "logs",
                                    "%s.%s" % (environment_id, log_file))
            try:
                if not os.path.exists(log_path):
                    continue
                with open(log_path, "rb") as logfd:
                    log = logfd.read().decode('utf-8')
            except Exception:
                self.logger.exception("Failed to open log file")
                continue
            self.logger.error("%s: %s", log_file, log)

    def terminate_docker(self):
        """
        Terminates any hanging running containers.
        """
        if not self.use_docker:
            return
        # First, stop all the docker containers that match the given names
        # If a previous run was cut off in between container creation and startup,
        # we must also remove the container ('docker rm <container>')
        for operation in ["stop", "rm"]:
            try:
                output = subprocess.check_output(['docker', 'ps', '--format', "'{{.Names}}'"]).decode('utf-8')
            except subprocess.CalledProcessError:
                self.logger.error("Failed to list container names -- is docker running?")
                return
            if output.strip():
                self.logger.debug("Cleaning up docker (%s)" % operation)
            for name in output.splitlines():
                if any(key in name for key in ["client", "censor", "server"]):
                    try:
                        subprocess.check_output(['docker', operation, name])
                    except subprocess.CalledProcessError:
                        pass

    def initialize_base_container(self, name):
        """
        Builds a base container with a given name and connects it to a given network.
        Also retrieves lower level settings and the IP address of the container.

        Args:
            name (str): Name of this docker container

        Returns:
            dict: Dictionary containing docker container object and relevant information
        """
        try:
            container = {}
            container["name"] = name
            # Note that this is _not_ safe to do in a multiprocessed context - must be run single threaded.
            container["container"] = self.docker_client.containers.run('base', detach=True, privileged=True, volumes={os.path.abspath(os.getcwd()): {"bind" : "/code", "mode" : "rw"}}, tty=True, remove=True, name=name)
            container["settings"] = self.apiclient.inspect_container(name)
        except docker.errors.NotFound:
            self.logger.error("Could not run container \"base\". Is docker not running, or does the base container not exist?")
            return None

        return container

    def get_pid(self, container):
        """
        Returns PID of first actively running python process.

        Args:
            container: Docker container object to query

        Returns:
            int: PID of Python process
        """
        pid = None
        try:
            output = subprocess.check_output(["docker", "exec", container.name, "ps", "aux"], stderr=subprocess.PIPE).decode('utf-8')
        except subprocess.CalledProcessError:
            return None
        for line in output.splitlines():
            if "root" not in line or "python" not in line:
                continue
            parts = line.split()
            # Try to parse out the pid to confirm we found it
            try:
                pid = int(parts[1])
                break
            except ValueError:
                raise
        return pid

    def stop_censor(self, environment):
        """
        Send SIGKILL to all remaining python processes in the censor container.
        This is done intentionally over a SIGINT or a graceful shutdown mecahnism - due to
        dynamics with signal handling in nfqueue callbacks (threads), SIGINTs can be ignored
        and graceful shutdown mechanisms may not be picked up (or be fast enough).

        The output this method parses is below:

        .. code-block:: bash

            # ps aux
            USER        PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
            root          1  0.1  0.0  21944  3376 pts/0    Ss+  13:30   0:00 /bin/bash
            root         14 24.0  0.4 200376 38564 ?        Ss   13:30   0:00 python code/censor_driver.py censor2 jgsko1rf trials/2018-10-30_06:30:48 60181
            root         32  0.0  0.0  19188  2400 ?        Rs   13:30   0:00 ps aux

        Args:
            environment (dict): Environment dictionary
        """
        port = environment["port"]
        queue_num = environment["queue_num"]
        if environment:
            pid = self.get_pid(environment["censor"]["container"])
            while pid:
                #self.logger.info("%s killing process %s in %s" % (environment["id"], str(pid), environment["censor"]["container"].name))
                try:
                    subprocess.check_call(["docker", "exec", "--privileged", environment["censor"]["container"].name, "kill", "-9", str(pid)])
                except subprocess.CalledProcessError:
                    pass
                pid = self.get_pid(environment["censor"]["container"])
                time.sleep(0.25)

            try:
                subprocess.check_call(["docker", "exec", "--privileged", environment["censor"]["container"].name, "iptables", "-D", "FORWARD", "-j", "NFQUEUE", "-p", "tcp", "--sport", str(port), "--queue-num", str(queue_num)])
            except subprocess.CalledProcessError:
                pass
            try:
                subprocess.check_call(["docker", "exec",  "--privileged",environment["censor"]["container"].name, "iptables", "-D", "FORWARD", "-j", "NFQUEUE", "-p", "tcp", "--dport", str(port), "--queue-num", str(queue_num)])
            except subprocess.CalledProcessError:
                pass

    def start_censor(self, environment, environment_id):
        """
        Starts the censor in the server environment container.

        Args:
            environment (dict): Environment dictionary
            environment_id (str): Environment ID of the censor to stop
        """
        assert self.use_docker, "Cannot start censor without enabling docker"
        port = environment["port"]
        queue_num = environment["queue_num"]
        try:
            self.logger.debug(" Starting censor %s with driver" % self.censor)
            command = ["docker", "exec",  "--privileged", environment["censor"]["container"].name,
                       "python", "code/censors/censor_driver.py",
                       "--censor", self.censor,
                       "--environment-id", environment_id,
                       "--output-directory", self.output_directory,
                       "--port", str(port),
                       "--log", "debug",
                       "--forbidden", self.args.get("bad_word", "ultrasurf"),
                       "--queue", str(queue_num)]
            self.exec_cmd(command)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            # Docker containers were killed out from under us - likely means
            # user forced a shutdown. Bail gracefully.
            return False
        except Exception:
            self.logger.exception("Failed out of start_censor")
        finally:
            self.logger.debug("Dockerized censor thread exiting")

    def read_fitness(self, ind):
        """
        Looks for this individual's fitness file on disk, opens it, and stores the fitness in the given individual.

        Args:
            ind (:obj:`actions.strategy.Strategy`): Individual to read fitness for
        """
        fitness_path = os.path.join(BASEPATH, self.output_directory, actions.utils.FLAGFOLDER, ind.environment_id + ".fitness")
        try:
            if os.path.exists(fitness_path):
                with open(fitness_path, "r") as fd:
                    ind.fitness = float(fd.read())
            elif not ind.fitness:
                self.logger.warning("Could not find fitness file for %s" % fitness_path)
                ind.fitness = -1000
        except:
            self.logger.exception("[%s] Failed to read fitness file" % ind.environment_id)
            ind.fitness = -1000

    def shutdown_container(self, container):
        """
        Tries to shutdown a given container and eats a NotFound exception if the container
        has already exited.

        Args:
            container: docker container object to call stop() on
        """
        try:
            container.stop()
        except docker.errors.NotFound:
            pass

    def shutdown_environment(self, environment):
        """
        Shuts down the evaluation environment.
        If Docker, shuts down server and client container.
        If a remote SSH connection, the connection is shut down.
        """
        if environment.get("docker"):
            self.shutdown_container(environment["client"]["container"])
            if self.censor:
                self.shutdown_container(environment["censor"]["container"])
                self.shutdown_container(environment["server"]["container"])
        elif environment.get("remote"):
            environment["remote"].close()

    def shutdown(self):
        """
        Shuts down all active environments
        """
        self.terminate_docker()


def collect_plugin(test_plugin, plugin_type, command, full_args, plugin_args):
    """
    Import a given plugin

    Args:
        test_plugin (str): Plugin name to import ("http")
        plugin_type (str): Component of plugin to import ("client")
        command (list): sys.argv or list of arguments
        full_args (dict): Parsed full list of arguments already maintained by the parent plugin
        plugin_args (dict): Dictionary of args specific to this plugin component

    Returns:
        Imported plugin class for instantiation later
    """
    cls = None
    try:
        _, cls = actions.utils.import_plugin(test_plugin, plugin_type)
        parsed_args = cls.get_args(command)
        # Only override the args if the plugin successfully parsed something; this allows
        # defaults from the evaluator or plugin to propagate.
        parsed_args = {k:v for k,v in parsed_args.items() if v or (not v and k not in full_args) }
        full_args.update(parsed_args)
        plugin_args.update(parsed_args)
    except ImportError as exc:
        pass
    return cls


def get_random_open_port():
    """
    Selects a random ephemeral port that is open.

    Returns:
        int: Open port
    """
    while True:
        port = random.randint(1024, 65000)
        # Bind TCP socket
        try:
            with socket.socket() as sock:
                # If we can bind, nothing is listening
                sock.bind(('', port))
                break
        except OSError:
            continue
    return port


def get_arg_parser(single_use=False):
    """
    Sets up argparse. This is done separately to enable collection of help messages.

    Args:
        single_use (bool, optional): whether this evaluator will only be used for one strategy, used to configure sane defaults
    """
    # Disable prefix matching to avoid prefix collisions for unseen plugin arguments
    parser = argparse.ArgumentParser(description='Evaluate a given strategy a given number of times.', allow_abbrev=False, prog="evaluator.py")
    # Type of evaluation
    parser.add_argument('--test-type', action='store', choices=actions.utils.get_plugins(), default="http", help="plugin to launch")
    parser.add_argument('--strategy', action='store', default="", required=single_use, help='strategy to evaluate')

    logging_group = parser.add_argument_group('control aspects of evaluator logging and storage')
    logging_group.add_argument('--log', action='store', choices=("debug", "info", "warning", "critical", "error"), help="Sets the log level")
    logging_group.add_argument('--output-directory', action='store', help="where to output results")
    logging_group.add_argument('--log-on-fail', action='store_true', help="dump the logs associated with each individual on strategy failure")
    logging_group.add_argument('--log-on-success', action='store_true', help="dump the logs associated with each individual on strategy success")

    external_group = parser.add_argument_group('control aspects of external resource usage')
    external_group.add_argument('--external-server', action='store_true', help="use an external server for testing.")
    external_group.add_argument('--external-client', action='store', help="use the given external client for testing.")

    networking_group = parser.add_argument_group('control aspects of evaluator networking configuration')
    networking_group.add_argument('--server-side', action="store_true", help="run the Geneva engine on the server side, not the client")
    networking_group.add_argument('--public-ip', action='store', help="public facing IP for this computer for server-side evaluation.")
    networking_group.add_argument('--routing-ip', action='store', help="locally facing IP for this computer, used for NAT")
    networking_group.add_argument('--sender-ip', action='store', help="IP address of sending machine, used for NAT")
    networking_group.add_argument('--forward-ip', action='store', help="IP address to forward traffic to")
    networking_group.add_argument('--act-as-middlebox', action='store_true', help="enables NAT mode. Requires --routing-ip, --sender-ip, and --forward-ip")
    networking_group.add_argument('--port', action='store', type=int, default=get_random_open_port(), help='default port to use')

    docker_group = parser.add_argument_group('control aspects of docker-specific options')
    docker_group.add_argument('--censor', action='store', help='censor to test against.', choices=censors.censor_driver.get_censors())
    docker_group.add_argument('--workers', action='store', default=1, type=int, help='controls the number of docker containers the evaluator will use.')
    docker_group.add_argument('--bad-word', action='store', help="forbidden word to test with", default="ultrasurf")

    evaluation_group = parser.add_argument_group('control aspects of evaluation')
    evaluation_group.add_argument('--runs', type=int, default=1, action='store', help="number of times each individual should be run per evaluation")
    evaluation_group.add_argument("--fitness-by", action='store', choices=('min', 'avg', 'max'), default='avg', help="if each individual is run multiple times, control how fitness is assigned.")
    evaluation_group.add_argument('--no-skip-empty', action='store_true', help="evaluate empty strategies (default: False).")

    return parser


def get_args(cmd, single_use=False):
    """
    Creates an argparser and collects arguments.

    Args:
        single_use (bool, optional): whether this evaluator will only be used for one strategy, used to configure sane defaults

    Returns:
        dict: parsed args
    """
    parser = get_arg_parser(single_use=single_use)

    args, _ = parser.parse_known_args(cmd)
    return vars(args)
