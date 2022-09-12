#!/usr/bin/env python3
import argparse
import asyncio
import hashlib
import json
import os.path
import ssl
from asyncio import StreamReader
from dataclasses import dataclass
from typing import cast

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicLogger


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


@dataclass
class WFile:
    path: str


class InFile(WFile, metaclass=Singleton):
    pass


class OutFile(WFile, metaclass=Singleton):
    pass


def get_sha256sum(filename: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(filename, 'rb') as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def cmp_file(file1: str, file2: str) -> bool:
    return get_sha256sum(file1) == get_sha256sum(file2)


class EchoBackProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.recv_fd = open(OutFile().path, 'wb')
        self.file_read = -1
        self.file_written = 0

    async def __stream_read(self, reader: StreamReader):
        assert self.file_read != 1, "send_file method must be called first !"
        tot_read = 0
        while tot_read != self.file_read:
            a = await reader.read(4096)
            tot_read += len(a)
            self.recv_fd.write(a)

        self.recv_fd.close()
        res = cmp_file(InFile().path, OutFile().path)
        os.unlink(OutFile().path)
        return res

    async def send_file(self, file: str, len_file: int):
        assert len_file > 0, f"len_file must be strictly positive. Received {len_file}"
        self.file_read = len_file

        reader, writer = await self.create_stream(is_unidirectional=False)
        reader_task = asyncio.create_task(self.__stream_read(reader))

        with open(file, 'rb') as f:
            while b := f.read(4096):
                writer.write(b)

        return await reader_task


async def main(host: str,
               port: int,
               quic_configuration: QuicConfiguration,
               file_data_send: str,
               create_protocol=EchoBackProtocol) -> None:
    async with connect(
            host,
            port,
            configuration=quic_configuration,
            create_protocol=create_protocol,
    ) as client:
        client = cast(EchoBackProtocol, client)
        answer = await client.send_file(file_data_send, os.path.getsize(file_data_send))
        if not answer:
            raise ValueError("The file received does not match the file sent")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Simple echo QUIC server")

    parser.add_argument('-p', '--port', dest='port', default=9876, type=int,
                        help='Listen to the specified port (default:9876)')
    parser.add_argument('--host', dest='host', type=str, required=True,
                        help='server address to contact')
    parser.add_argument('-a', '--alpn', dest='alpn', required=False, default='echo-server',
                        type=str, help='alpn string used by the server (default: echo-server)')
    parser.add_argument('-i', '--in_file', dest='in_file', type=str, required=True,
                        help='File to send to the server')
    parser.add_argument('-o', '--out_file', dest='out_file', type=str, required=True,
                        help='File path to store what the server sends to this client. '
                             'It is automatically removed when this program exits.')
    parser.add_argument('-q', '--qlog', dest='qlog', type=str, required=False, default=None,
                        help='Enable qlog and log all data to the file passed as parameter of this argument.')
    parser.add_argument('-c', '--certificate', dest='certificate', required=False, default=None,
                        help='Provide a certificate for client authentication')
    parser.add_argument('-k', '--key', dest='key', required=False, default=None,
                        help='Client private key')

    cli_args = parser.parse_args()

    InFile(cli_args.in_file)
    OutFile(cli_args.out_file)

    secrets = open('/tmp/keys.tls', 'a')

    q_log = QuicLogger() if cli_args.qlog is not None else None

    configuration = QuicConfiguration(
        alpn_protocols=[cli_args.alpn],
        is_client=True,
        quic_logger=q_log,
        secrets_log_file=secrets,
        verify_mode=ssl.CERT_NONE,
    )

    if cli_args.certificate is not None:
        configuration.load_cert_chain(cli_args.certificate, cli_args.key)

    try:
        asyncio.run(
            main(host=cli_args.host,
                 port=cli_args.port,
                 quic_configuration=configuration,
                 file_data_send=cli_args.in_file)
        )
    except KeyboardInterrupt:
        exit(0)
    finally:
        secrets.close()
        if cli_args.qlog is not None:
            with open("/tmp/q_log.qlog", 'w') as f:
                json.dump(q_log.to_dict(), f)
