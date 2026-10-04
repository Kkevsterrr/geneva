"""
Regression test for SSH channel-window exhaustion in remote_exec_cmd

The server sends more than the client receive window to stdout and stderr and then reports its exit status.
Waiting for that status before reading output deadlocks because the server cannot finish sending either stream.
"""
import logging
import socket
import threading
import time

import paramiko
import pytest

from evaluator import Evaluator


WINDOW_SIZE = 65536
STDOUT = b"stdout-marker\n" * 8192
STDERR = b"stderr-marker\n" * 8192


class _TestServer(paramiko.ServerInterface):
    def __init__(self):
        self.command_started = threading.Event()

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return (paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    def check_channel_exec_request(self, channel, command):
        if command != b"emit-both-streams":
            return False
        self.command_started.set()
        return True


class _RemoteClient:
    """Provide SSHClient.exec_command's three streams on a configured Transport"""
    def __init__(self, transport):
        self.transport = transport
        self.commands_started = 0
        self.channels = []

    def exec_command(self, command, timeout=None):
        self.commands_started += 1
        channel = self.transport.open_session(timeout=timeout)
        self.channels.append(channel)
        channel.settimeout(timeout)
        channel.exec_command(command)
        return (channel.makefile_stdin("wb"), channel.makefile("r"), channel.makefile_stderr("r"))


def test_remote_exec_cmd_drains_both_streams_before_exit_status():
    assert len(STDOUT) > WINDOW_SIZE
    assert len(STDERR) > WINDOW_SIZE

    #A socket pair keeps the SSH test local. Only the client Transport has a
    #small receive window; the server must obey it as it sends channel data
    client_socket, server_socket = socket.socketpair()
    client_transport = paramiko.Transport(client_socket, default_window_size=WINDOW_SIZE)
    server = _TestServer()
    server_done = threading.Event()
    server_errors = []

    def serve():
        transport = None
        try:
            transport = paramiko.Transport(server_socket)
            transport.add_server_key(paramiko.RSAKey.generate(1024))
            transport.start_server(server=server)
            channel = transport.accept(5)
            if channel is None or not server.command_started.wait(5):
                raise AssertionError("SSH command was not started")

            #the exit status packet is deliberately sent only after both
            #writes complete. With the old evaluator, sendall cannot finish.
            channel.sendall(STDOUT)
            channel.sendall_stderr(STDERR)
            channel.send_exit_status(23)
            channel.shutdown_write()
            server_done.wait(5)
        except Exception as exc:
            if not server_done.is_set():
                server_errors.append(exc)
        finally:
            if transport is not None:
                transport.close()
            server_socket.close()

    server_thread = threading.Thread(target=serve, daemon=True)
    server_thread.start()
    call_result = []
    call_errors = []
    caller = None

    try:
        client_transport.start_client(timeout=5)
        client_transport.auth_password("test", "test")
        remote = _RemoteClient(client_transport)

        def execute():
            try:
                #__init__ sets up real evaluation resources; this test only
                #exercises the SSH command method and needs none of them
                instance = Evaluator.__new__(Evaluator)
                call_result.append(instance.remote_exec_cmd(remote, "emit-both-streams", logging.getLogger(__name__), timeout=3, verbose=False))
            except Exception as exc:
                call_errors.append(exc)

        caller = threading.Thread(target=execute, daemon=True)
        caller.start()
        caller.join(4)

        #on the original implementation this fails promptly: recv_exit_status
        #waits while the server is blocked sending into a full receive window
        assert not caller.is_alive(), "remote_exec_cmd blocked on SSH exit status"
        assert not call_errors, "remote_exec_cmd raised: %r" % call_errors
        assert not server_errors, "SSH server failed: %r" % server_errors
        assert call_result == [(STDOUT.decode("ascii").splitlines(True), STDERR.decode("ascii").splitlines(True))]

    finally:

        server_done.set()
        client_transport.close()
        if caller is not None:
            caller.join(2)
        server_thread.join(5)

def _run_command_case(send_output, timeout=3, caller_deadline=4):
    """Run the real SSH method with a configurable server response"""
    client_socket, server_socket = socket.socketpair()
    client_transport = paramiko.Transport(
        client_socket, default_window_size=WINDOW_SIZE)
    server = _TestServer()
    server_done = threading.Event()
    server_errors = []

    def serve():
        transport = None
        try:

            transport = paramiko.Transport(server_socket)
            transport.add_server_key(paramiko.RSAKey.generate(1024))
            transport.start_server(server=server)
            channel = transport.accept(5)
            if channel is None or not server.command_started.wait(5):
                raise AssertionError("SSH command was not started")
            send_output(channel, server_done)

        except Exception as exc:
            if not server_done.is_set():
                server_errors.append(exc)

        finally:

            if transport is not None:
                transport.close()
            server_socket.close()

    server_thread = threading.Thread(target=serve, daemon=True)
    server_thread.start()
    result, call_errors = [], []
    caller = None

    try:
        client_transport.start_client(timeout=5)
        client_transport.auth_password("test", "test")
        remote = _RemoteClient(client_transport)

        def execute():
            try:
                instance = Evaluator.__new__(Evaluator)
                result.append(instance.remote_exec_cmd(remote, "emit-both-streams", logging.getLogger(__name__), timeout=timeout, verbose=False))
            except Exception as exc:
                call_errors.append(exc)

        caller = threading.Thread(target=execute, daemon=True)
        started = time.monotonic()
        caller.start()
        caller.join(caller_deadline)
        elapsed = time.monotonic() - started

        assert not caller.is_alive(), "remote_exec_cmd exceeded the test deadline"
        assert not call_errors, "remote_exec_cmd raised: %r" % call_errors
        assert not server_errors, "SSH server failed: %r" % server_errors
        assert len(result) == 1

        return result[0], remote.commands_started, remote.channels[0].closed, elapsed

    finally:

        server_done.set()
        client_transport.close()
        if caller is not None:
            caller.join(2)
        server_thread.join(5)


def test_remote_exec_cmd_times_out_without_replaying_command():
    def never_finish(channel, done):
        #The server accepts exec but never sends data, EOF, or exit status
        done.wait(5)

    output, attempts, channel_closed, elapsed = _run_command_case(never_finish, timeout=0.2, caller_deadline=2)
    assert output == ([], [])
    assert attempts == 1
    assert channel_closed
    assert elapsed < 2


@pytest.mark.parametrize("stdout, stderr, expected", [(b"first\nlast", b"warning\n", (["first\n", "last"], ["warning\n"])), (b"", b"", ([], []))])
def test_remote_exec_cmd_small_output(stdout, stderr, expected):
    def send_small(channel, done):
        if stdout:
            channel.sendall(stdout)
        if stderr:
            channel.sendall_stderr(stderr)
        channel.send_exit_status(7)
        channel.shutdown_write()
        done.wait(5)

    output, attempts, channel_closed, _ = _run_command_case(send_small)
    assert output == expected
    assert attempts == 1
    assert channel_closed


def test_remote_exec_cmd_drains_interleaved_streams():
    stdout_chunk = b"O" * 8191 + b"\n"
    stderr_chunk = b"E" * 8191 + b"\n"
    chunks_per_stream = 32
    assert len(stdout_chunk) * chunks_per_stream > WINDOW_SIZE
    assert len(stderr_chunk) * chunks_per_stream > WINDOW_SIZE

    def send_interleaved(channel, done):
        for _ in range(chunks_per_stream):
            channel.sendall(stdout_chunk)
            channel.sendall_stderr(stderr_chunk)
        channel.send_exit_status(9)
        channel.shutdown_write()
        done.wait(5)

    output, attempts, channel_closed, _ = _run_command_case(send_interleaved)
    assert output == ([stdout_chunk.decode()] * chunks_per_stream, [stderr_chunk.decode()] * chunks_per_stream)
    assert attempts == 1
    assert channel_closed
