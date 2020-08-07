"""
Client

Run by the evaluator, sends a TLS Client Hello with the ESNI extension, followed by two test packets.
"""

import argparse
import binascii as bi
import os
import socket
import time

socket.setdefaulttimeout(1)

from plugins.plugin_client import ClientPlugin


class ESNIClient(ClientPlugin):
    """
    Defines the ESNI client.
    """
    name = "esni"

    def __init__(self, args):
        """
        Initializes the esni client.
        """
        ClientPlugin.__init__(self)
        self.args = args

    @staticmethod
    def get_args(command):
        """
        Defines required args for this plugin
        """
        super_args = ClientPlugin.get_args(command)
        parser = argparse.ArgumentParser(description='ESNI Client')

        parser.add_argument('--server', action='store', help="server to connect to")

        args, _ = parser.parse_known_args(command)
        args = vars(args)

        super_args.update(args)
        return super_args

    def run(self, args, logger, engine=None):
        """
        Try to make a forbidden GET request to the server.
        """
        fitness = 0
        port = int(args["port"])
        server = args["server"]
        # Client Hello with the ESNI extension
        msg = b'16030103ae010003aa0303d992f9c22fbe7a7cdbc9619924bd9cc13c057f5f3da1829426cb0944292705152033c5be80af6de7633e07680125e27e3f7b80ff5e9b3cbe5278434c90b9e0e5fa0024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035000a0100033d00170000ff01000100000a000e000c001d00170018001901000101000b000201000010000e000c02683208687474702f312e310005000501000000000033006b0069001d002019570ada256d971048b34d3e9ff5607588bf10cfb6c064fc45a0fc401d9a7c470017004104ea047fd2e0fc3314de4bf03ee6205134f0d15c07f62b77625a95dc194ce8fb88cc16e53c8b400ba463915b87480b247851c095abdb0d3d5d5b14dd77dcd73750002b00050403040303000d0018001604030503060308040805080604010501060102030201002d00020101ffce016e1301001d00203652aaf122dc47dcf9fa8c37377476d050e54119adfb518f7aabd842ac97d23b00205a30e70593f57708370310ecf7054e488a62eb11e01fd059851c442d453d15c5012441910eec152c4df5ff28bf5cddb1a2e54e8595197e3dc36325145ad50a7842eb3860c8fc6ac5c1794017101365c6122abb3b81f31f5f4204eebb244252d22600734424d875948657b892d3aab3310491aff3b5126f1186bd9c321fb446cf2a41985dd206364ea28c3f8aafeafc62e039f157c3f2703a35448d2d16dcf2d5055ce58c024a5b4eb780fc5128af4ba4e90d6eef1b3cf30a5b2000448d65d6af4fffabeb91e1ed2093fdcc6ffd87ceb94429864ddb657e6316654631193fd25840e51645e1708d351140dd6eeefb80ddbaebb250b2975a1d5f291d99f89de4553d083f1b9820a3ee6976357cff433b7eb77febb3eb0db012154154d3e19b4409f8afa11aa1baeb0b7663d97f0caca2b11ed971fc574588e76a37aa4259593fe8e07fbbca27fa001c00024001002900eb00c600c07f87fafe9de4168227aeec4540f1aaeae43ff61a353f5480420ac3c33f90003fe6f501080bf04f22576a0cc1db8dc83d37b25859a81ce0277364a1794cde1c60f3b94175477beff56db7f9e2b83b31383b7d8b5da20834fb0a63d7ba2e42ad3dfa21666ed8621f34273ac5c273d7f492750e3df3bae36e398ddf83d4a7c36f639087f14eb1f7bfb2c7c0c736d69bcdbf21158c07b7088b95e5bcd08138d6b511f6492d7d93bb3729641519097b970cfeffa5882c67111dcf5d7966a1c58b4edb6e8c905a002120e47ccba37d89e4c1d979c6ef954d1cd946eff0d3119aa2b4d6411138aec74579'
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(5)
            client.connect((server, port))
            client.sendall(bi.unhexlify(msg))
            time.sleep(2)
            client.sendall(b"test packet")
            time.sleep(2)
            client.sendall(b"test packet 2")
            server_data = client.recv(1024)
            logger.debug("Data recieved: %s", server_data.decode('utf-8', 'ignore'))
            fitness += 100
            client.close()
        except socket.timeout:
            # Happens on connect, not sendall
            logger.debug("Client: Timeout")
            fitness -= 110
        except socket.error as exc:
            fitness -= 100
            logger.exception("Socket error caught in client esni test.")
        except Exception:
            logger.exception("Exception caught in client esni test.")
            fitness = -120
        finally:
            logger.debug("Client finished esni test.")
        return fitness * 4
