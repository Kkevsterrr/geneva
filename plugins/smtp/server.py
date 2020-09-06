import argparse
import os
import socket
import subprocess
import time

from plugins.plugin_server import ServerPlugin

BASEPATH = os.path.dirname(os.path.abspath(__file__))


class SMTPServer(ServerPlugin):
    """
    Defines the SMTP client.
    """
    name = "smtp"
    def __init__(self, args):
        """
        Initializes the SMTP client.
        """
        ServerPlugin.__init__(self)
        self.args = args
        if args:
            self.port = args["port"]

    @staticmethod
    def get_args(command):
        """
        Defines arguments for this plugin
        """
        super_args = ServerPlugin.get_args(command)

        parser = argparse.ArgumentParser(description='SMTP Server')

        parser.add_argument('--smtp-request', action='store_true', help='Send an SMTP byte string that triggers censorship')

        args, _ = parser.parse_known_args(command)
        args = vars(args)
        super_args.update(args)
        return super_args

    def run(self, args, logger):
        """
        Initializes the SMTP server.
        """
        logger.debug("SMTP server initializing")
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
            logger.exception("Caught exception in smtp run")
            return

        try:
            connection, client_address = self.get_request(control_socket)
            if not connection:
                logger.error("Failed to get connection")
                return

            bad_word = args["bad_word"]
            expected_msg = bad_word

            if args.get('smtp_request'):
                expected_msg = b'MAIL FROM: xiazai@upup.info \r\n'

            if type(expected_msg) == str:
                expected_msg = expected_msg.encode()

            # SMTP data back and forth
            tries = args.get("tries", 1)
            for i in range(0, int(tries)):
                msg = b''
                while msg !=  expected_msg:
                    msg += connection.recv(1024)
                time.sleep(1)
                connection.sendall(b'k')

            time.sleep(1)
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
