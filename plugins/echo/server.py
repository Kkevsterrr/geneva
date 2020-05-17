import argparse
import os
import socket
import subprocess

from plugins.plugin_server import ServerPlugin

BASEPATH = os.path.dirname(os.path.abspath(__file__))


class EchoServer(ServerPlugin):
    """
    Defines the Echo client.
    """
    name = "echo"
    def __init__(self, args):
        """
        Initializes the Echo client.
        """
        ServerPlugin.__init__(self)

    @staticmethod
    def get_args(command):
        """
        Defines arguments for this plugin
        """
        super_args = ServerPlugin.get_args(command)

        parser = argparse.ArgumentParser(description='Echo Server')

        args, _ = parser.parse_known_args(command)
        args = vars(args)
        super_args.update(args)
        return super_args

    def run(self, args, logger):
        """
        Initializes the Echo server.
        """
        logger.debug("Echo server initializing")
        try:
            port = int(args["port"])
            control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Allow socket re-use
            control_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_address = ('0.0.0.0', port)
            logger.debug("Binding to server address 0.0.0.0:%d" % port)
            control_socket.bind(server_address)
            control_socket.settimeout(5)
            control_socket.listen(1)
        except:
            logger.exception("Caught exception in echo run")
            return

        try:
            connection, client_address = self.get_request(control_socket)
            if not connection:
                logger.error("Failed to get connection")
                return
            # Echo data back and forth
            for i in range(0, 5):
                data = connection.recv(1024)
                connection.sendall(data)

            connection.close()
        except socket.error as e:
            if e.errno == 104:
                logger.debug("Server: Connection RST.")
            else:
                logger.debug("Server: Client quit.")
        except socket.ConnectionResetError:
            logger.debug("Server: Connection RST.")
        except Exception:
            logger.exception("Failed during server communication.")
        finally:
            logger.debug("Server exiting")

    def get_request(self, control_socket):
        """
        Get a request from the socket.
        """
        while True:
            try:
                sock, addr = control_socket.accept()
                sock.settimeout(5)
                return (sock, addr)
            except socket.timeout:
                pass
        return (None, None)

    def stop(self):
        """
        Stops this server.
        """
        ServerPlugin.stop(self)
