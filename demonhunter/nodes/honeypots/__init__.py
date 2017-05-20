import asyncio
import json
<<<<<<< HEAD
import ssl
import os
=======
import logging

from demonhunter.core.loggers.logfile import FileLogger
>>>>>>> RevengeComing/master


class BaseHandler:
    # https://svn.nmap.org/nmap/nmap-service-probes

    def save_data(self, data):
        if self.honeypot.sqlite:
            self.save_in_sqlite(data)
        if self.honeypot.logfile:
            self.save_logfile(data)
        self.alter_agents(data)

    def alter_agents(self, data):
        for agent in self.honeypot.agents:
            agent.send_data(data)

    def save_in_sqlite(self, data):
        pass

    def save_logfile(self, data):
        self.honeypot.file_logger.log(data)


class BaseHoneypot(object):
    
    active_attacks = 0

    def __init__(self, logfile=None, sqlite=None, interfaces=['0.0.0.0'], agents=None):
        self.logfile = logfile
        self.sqlite = sqlite
        self.interfaces = interfaces

        if self.logfile:
            self.file_logger = FileLogger(self.logfile)

        if not agents:
            self.agents = []

    def create_server(self, loop):
        coro = loop.create_server(lambda: self.handler(self), self.interfaces, self.port)
        server = loop.run_until_complete(coro)
        for socket in server.sockets:
            logging.info('Serving on {0}'.format(socket.getsockname()))
        return server


class Agent():
    def __init__(self, target, honeypots, loop, certificate, port, agent_password=None):
        self.loop = loop
        self.targets = target
        for honeypot in honeypots:
            honeypot.agents.append(self)
        self.agent_password = None if not agent_password else agent_password.encode()
        self.port = port
        self.certificate = certificate
        if self.certificate is not None:
            assert os.path.exists(self.certificate)
            self.sc = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.certificate)
        print("Connecting to AgentManager at {}".format(self.port))

    # TODO: Secure the transport ssl/or something.
    def send_data(self, data):
        data = json.dumps(data)
        for target in self.targets:
            # if the certificate is present we send via ssl if not, we go the old way
            if self.certificate is None:
                coro = self.loop.create_connection(lambda: AgentProtocol(data, self.agent_password),
                                               target, self.port)
                self.loop.call_soon_threadsafe(asyncio.async, coro)
            else:
                coro = self.loop.create_connection(lambda: AgentProtocol(data, self.agent_password),
                                               target, self.port, ssl=self.sc)
                self.loop.call_soon_threadsafe(asyncio.async, coro)


class AgentProtocol(asyncio.Protocol):
    state = 0

    def __init__(self, message, agent_password):
        self.message = message
        self.agent_password = agent_password

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        if data == b"Hello Agent!":
            self.send_data()
        elif data == b"Hello Agent! Give Me The Night Word":
            if self.agent_password:
                self.transport.write(self.agent_password)
            else:
                logging.warning("AgentManager Asks for password !? did you forget to set a password ?")
                self.transport.close()

    def send_data(self):
        self.transport.write(str.encode(self.message))

    def connection_lost(self, exc):
        pass
