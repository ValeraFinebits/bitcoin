#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Send Payjoin v2 through wallet RPC to an upstream payjoin-cli receiver."""

from contextlib import ExitStack, closing, contextmanager
from decimal import Decimal
from http.client import HTTPConnection, HTTPSConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from math import ceil
import os
from pathlib import Path
import socket
import ssl
import subprocess
from threading import Event, Thread
from urllib.parse import urlsplit

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import assert_equal, assert_raises_rpc_error, rpc_port


class PayjoinTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.wallet_names = []
        self.extra_args = [["-fallbackfee=0.00001", "-addresstype=bech32", "-changetype=bech32", "-deprecatedrpc=bip125"]]

    def add_options(self, parser):
        parser.add_argument("--payjoin-cli", help="Path to the pinned upstream payjoin-cli executable")
        parser.add_argument("--payjoin-test-services", help="Path to the test-FFI TestServices launcher")

    def skip_test_if_missing_module(self):
        if not self.options.payjoin_cli and not self.options.payjoin_test_services:
            raise SkipTest("requires --payjoin-cli and --payjoin-test-services")
        for component in ["ENABLE_PAYJOIN", "ENABLE_WALLET", "ENABLE_BITCOIND", "ENABLE_CLI"]:
            assert self.config.getboolean("components", component), f"Payjoin test requires {component}"
        for option in ["payjoin_cli", "payjoin_test_services"]:
            value = getattr(self.options, option)
            assert value, f"Missing --{option.replace('_', '-')}"
            executable = Path(value).resolve(strict=True)
            assert executable.is_file() and os.access(executable, os.X_OK), f"Not executable: {executable}"
            setattr(self.options, option, str(executable))
        self.skip_if_no_wallet()

    @contextmanager
    def process(self, name, args, directory, env=None):
        """Keep child output in files and reap children before closing their streams."""
        stdout_path = directory / f"{name}.stdout"
        stderr_path = directory / f"{name}.stderr"
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            child = subprocess.Popen(args, cwd=directory, env=env, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr)
            try:
                yield child, stdout_path
            except Exception:
                for path in [stdout_path, stderr_path]:
                    self.log.error("%s:\n%s", path, path.read_text(encoding="utf8", errors="replace")[-8000:])
                raise
            finally:
                try:
                    child.stdin.close()
                except BrokenPipeError:
                    pass
                try:
                    child.wait(timeout=5 * self.options.timeout_factor)
                except subprocess.TimeoutExpired:
                    child.terminate()
                    try:
                        child.wait(timeout=5 * self.options.timeout_factor)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5 * self.options.timeout_factor)

    def wait_for_line(self, child, path, predicate):
        result = None
        with path.open(encoding="utf8") as output:
            def ready():
                nonlocal result
                while True:
                    position = output.tell()
                    line = output.readline()
                    if not line.endswith("\n"):
                        output.seek(position)
                        break
                    if predicate(line.strip()):
                        result = line.strip()
                        return True
                assert child.poll() is None, f"Child exited with {child.returncode} before expected output in {path}"
                return False

            self.wait_until(ready, timeout=30)
        return result

    @contextmanager
    def receiver_relay(self, relay_url, output, timeout):
        """Hold the receiver's proposal acknowledgement until Core publishes it."""
        relay = urlsplit(relay_url)
        assert_equal(relay.scheme, "http")
        held = Event()
        release = Event()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                replying = output.exists() and "Fallback transaction received." in output.read_text(encoding="utf8")
                body = self.rfile.read(int(self.headers["Content-Length"]))
                with closing(HTTPConnection(relay.hostname, relay.port, timeout=timeout)) as connection:
                    connection.request("POST", self.path, body, {"Content-Type": self.headers["Content-Type"]})
                    response = connection.getresponse()
                    body = response.read()
                    if replying and response.status == 200:
                        held.set()
                        if not release.wait(timeout):
                            self.send_error(504, "Core did not publish before the receiver deadline")
                            return
                    self.send_response(response.status)
                    self.send_header("Content-Type", response.getheader("Content-Type", "application/ohttp-res"))
                    self.send_header("Content-Length", str(len(body)))
                    try:
                        self.end_headers()
                        self.wfile.write(body)
                    except (BrokenPipeError, ConnectionResetError):
                        pass

            def log_message(self, *_args):
                pass

        with HTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = Thread(target=server.serve_forever)
            thread.start()
            try:
                yield f"http://127.0.0.1:{server.server_port}", held, release
            finally:
                release.set()
                server.shutdown()
                thread.join()

    def test_admission(self, sender, request):
        self.log.info("Invalid requests do not create payments or claim their idempotency key")
        before = sender.listpayjoins()
        locks = sender.listlockunspent()
        assert_raises_rpc_error(-8, "Unknown", sender.getpayjoin, "01" * 32)
        assert_raises_rpc_error(-8, "Unknown", sender.cancelpayjoin, "01" * 32)
        assert_raises_rpc_error(-8, None, sender.getpayjoin, "not-a-payment")
        for patch in [{"timeout": 0}, {"timeout": 86401}, {"timeout": 1.5},
                      {"request_id": ""}, {"request_id": "x" * 129}, {"request_id": "\0"},
                      {"request_id": "é" * 65}, {"amount": 2}]:
            assert_raises_rpc_error(-8, None, sender.sendpayjoin, **{**request, **patch})
        for patch in [{"fee_rate": 0}, {"max_total_fee": 0}, {"max_total_fee": 1}]:
            assert_raises_rpc_error(-4, None, sender.sendpayjoin, **{**request, **patch})
        without_amount = request["uri"].split("?")[0] + "?" + "&".join(
            part for part in request["uri"].split("?")[1].split("&") if not part.startswith("amount="))
        assert_raises_rpc_error(-8, "amount is required", sender.sendpayjoin, **{**request, "uri": without_amount})
        assert_equal(sender.listpayjoins(), before)
        assert_equal(sender.listlockunspent(), locks)

    def test_not_sent(self, sender, request):
        self.log.info("A known unsent request keeps its key but cancellation releases its inputs")
        locks = sender.listlockunspent()
        request = {**request, "request_id": "not-sent"}
        request.pop("timeout")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as unavailable:
            unavailable.bind(("127.0.0.1", 0))
            request["relay"] = f"http://127.0.0.1:{unavailable.getsockname()[1]}"
            accepted = sender.sendpayjoin(**{**request, "timeout": None})
            payment_id = accepted["payment_id"]
            self.wait_until(lambda: sender.getpayjoin(payment_id)["phase"] == "attention")
        payment = sender.getpayjoin(payment_id)
        assert_equal(payment["problem"]["code"], "delivery")
        assert_equal(payment["possibly_exposed"], False)
        assert_equal(payment["reservations"]["owned"], True)
        duplicate = sender.sendpayjoin(**request)
        assert_equal(duplicate["payment_id"], payment_id)
        assert_equal(duplicate["duplicate"], True)
        assert_raises_rpc_error(-8, "different parameters", sender.sendpayjoin, **{**request, "timeout": 120})
        assert_equal(sender.retrypayjoin(payment_id, "retry_signing")["result"], "refused")
        assert_raises_rpc_error(-1, None, sender.retrypayjoin, payment_id)
        assert_raises_rpc_error(-8, "action must be", sender.retrypayjoin, payment_id, "restart")
        cancelled = sender.cancelpayjoin(payment_id)
        assert_equal(cancelled["result"], "completed")
        assert_equal(cancelled["payment"]["phase"], "cancelled")
        assert_equal(cancelled["payment"]["possibly_exposed"], False)
        assert_equal(cancelled["payment"]["reservations"]["owned"], False)
        assert_equal(sender.listlockunspent(), locks)
        return payment_id

    def run_test(self):
        node = self.nodes[0]
        node.createwallet("sender")
        node.createwallet("receiver")
        sender = node.get_wallet_rpc("sender")
        receiver = node.get_wallet_rpc("receiver")
        self.generatetoaddress(node, 101, sender.getnewaddress())
        sender.sendtoaddress(receiver.getnewaddress(), Decimal("2"))
        self.generatetoaddress(node, 1, sender.getnewaddress())
        coins = receiver.listunspent()
        assert_equal(len(coins), 1)
        contribution = coins[0]
        balance_before = receiver.getbalance()
        amount = Decimal("0.001")
        max_fee = Decimal("0.0001")
        directory = Path(self.options.tmpdir) / "payjoin"
        directory.mkdir()
        certificate = directory / "localhost.der"
        exchange_timeout = min(86400 // 3, max(1, ceil(120 * self.options.timeout_factor)))

        env = {key: value for key, value in os.environ.items() if not key.lower().endswith("_proxy")}
        with ExitStack() as children:
            services, services_output = children.enter_context(self.process(
                "services", [self.options.payjoin_test_services, str(certificate)], directory, env))
            ready = json.loads(self.wait_for_line(services, services_output, lambda line: line.startswith("{")))
            endpoint = urlsplit(ready["directory"])
            trust = ssl.create_default_context(cadata=ssl.DER_cert_to_PEM_cert(certificate.read_bytes()))
            keys = directory / "ohttp-keys"
            with closing(HTTPSConnection(endpoint.hostname, endpoint.port, context=trust, timeout=exchange_timeout)) as connection:
                connection.request("GET", "/.well-known/ohttp-gateway", headers={"Accept": "application/ohttp-keys"})
                response = connection.getresponse()
                assert_equal(response.status, 200)
                keys.write_bytes(response.read())
            receiver_relay, reply_held, release_reply = children.enter_context(self.receiver_relay(
                ready["relay"], directory / "receiver.stdout", exchange_timeout))
            env.update(XDG_CONFIG_HOME=str(directory / "config"), RUST_LOG="warn")
            cli, cli_output = children.enter_context(self.process("receiver", [
                self.options.payjoin_cli, "--bip77", "--db-path", str(directory / "receiver.sqlite"),
                "--rpchost", f"http://127.0.0.1:{rpc_port(0)}/wallet/receiver",
                "--cookie-file", str(node.chain_path / ".cookie"), "--root-certificate", str(certificate),
                "--ohttp-relays", receiver_relay, "--ohttp-keys", str(keys),
                "receive", "100000", "--pj-directories", ready["directory"],
                "--expire-in", str(3 * exchange_timeout), "--max-fee-rate", "10",
            ], directory, env))
            children.callback(release_reply.set)
            uri = self.wait_for_line(cli, cli_output, lambda line: line.startswith("bitcoin:"))
            request = dict(uri=uri, relay=ready["relay"], fee_rate=1, max_total_fee=max_fee,
                           timeout=exchange_timeout, request_id="invoice=1")
            self.test_admission(sender, request)
            self.log.info("Send through bitcoin-cli and repeat the same idempotency key")
            accepted = node.cli("-rpcwallet=sender").sendpayjoin(**request)
            payment_id = accepted["payment_id"]
            assert_equal(accepted["duplicate"], False)
            repeated = sender.sendpayjoin(**request)
            assert_equal(repeated["payment_id"], payment_id)
            assert_equal(repeated["duplicate"], True)
            positional = node.cli("-rpcwallet=sender").sendpayjoin(
                uri, ready["relay"], None, 1, max_fee, exchange_timeout, "invoice=1")
            assert_equal(positional["payment_id"], payment_id)
            assert_equal(positional["duplicate"], True)
            assert_raises_rpc_error(-8, "different parameters", sender.sendpayjoin,
                                    **{**request, "timeout": exchange_timeout + 1})
            assert_equal([p["payment_id"] for p in sender.listpayjoins()], [payment_id])
            assert_equal(receiver.listpayjoins(), [])
            assert_raises_rpc_error(-8, "Unknown Payjoin payment_id in this wallet load", receiver.getpayjoin, payment_id)

            original_hex = self.wait_for_line(cli, cli_output, lambda line: len(line) > 20 and all(c in "0123456789abcdef" for c in line))
            original = node.decoderawtransaction(original_hex)

            def published():
                assert services.poll() is None, "TestServices exited during exchange"
                assert cli.poll() in [None, 0], f"Receiver failed with {cli.returncode}"
                payment = sender.getpayjoin(payment_id)
                assert "problem" not in payment, payment
                return payment["phase"] == "published"

            self.wait_until(published, timeout=exchange_timeout / self.options.timeout_factor)
            payment = sender.getpayjoin(payment_id)
            txid = payment["selected"]["txid"]
            assert_equal(original["txid"], payment["original"]["txid"])
            assert_equal(original["hash"], payment["original"]["wtxid"])
            assert txid != original["txid"]
            assert txid in node.getrawmempool()
            assert original["txid"] not in node.getrawmempool()
            self.wait_until(reply_held.is_set)
            assert cli.poll() is None
            assert "Response successful." not in cli_output.read_text(encoding="utf8")
            release_reply.set()
            selected = node.getrawtransaction(txid, True)
            original_inputs = {(i["txid"], i["vout"]) for i in original["vin"]}
            selected_inputs = {(i["txid"], i["vout"]) for i in selected["vin"]}
            receiver_input = (contribution["txid"], contribution["vout"])
            assert receiver_input not in original_inputs
            assert_equal(selected_inputs, original_inputs | {receiver_input})
            assert all(i.get("txinwitness") for i in selected["vin"])
            recipient_script = receiver.getaddressinfo(urlsplit(uri).path)["scriptPubKey"]
            recipient_outputs = [out for out in selected["vout"] if out["scriptPubKey"]["hex"] == recipient_script]
            assert_equal(len(recipient_outputs), 1)
            assert contribution["amount"] + amount - max_fee <= recipient_outputs[0]["value"] <= contribution["amount"] + amount
            assert node.getmempoolentry(txid)["fees"]["base"] <= max_fee

            cli.wait(timeout=exchange_timeout)
            assert_equal(cli.returncode, 0)
            assert "Payjoin transaction detected in the mempool!" in cli_output.read_text(encoding="utf8")
            self.log.info("The receiver completed; confirm the selected transaction")
            block = self.generatetoaddress(node, 1, sender.getnewaddress())[0]
            self.wait_until(lambda: sender.getpayjoin(payment_id)["phase"] == "confirmed")
            settled = sender.getpayjoin(payment_id)
            assert_equal(settled["selected"]["presence"], "confirmed")
            assert_equal(settled["reservations"]["owned"], False)
            assert_equal(settled["storage_uncertain"], False)
            assert "problem" not in settled, settled
            locks = {(coin["txid"], coin["vout"]) for coin in sender.listlockunspent()}
            assert original_inputs.isdisjoint(locks)
            assert amount - max_fee <= receiver.getbalance() - balance_before <= amount

            self.log.info("RPC reads follow a reorg without resuming negotiation")
            node.invalidateblock(block)
            changed = sender.getpayjoin(payment_id)
            assert_equal(changed["phase"], "attention")
            assert_equal(changed["problem"]["code"], "observed_spend")
            assert_equal(changed["selected"]["txid"], txid)
            assert changed["selected"]["presence"] != "confirmed"
            assert_equal(changed["reservations"]["owned"], False)
            node.reconsiderblock(block)
            assert_equal(sender.getpayjoin(payment_id)["phase"], "confirmed")

            self.log.info("Network policy rejects new payments while reads and duplicates remain available")
            node.setnetworkactive(False)
            try:
                assert_equal(sender.sendpayjoin(**request)["payment_id"], payment_id)
                assert_raises_rpc_error(-9, "active node networking", sender.sendpayjoin,
                                        **{**request, "request_id": "network-disabled"})
                assert_equal(sender.getpayjoin(payment_id)["phase"], "confirmed")
                assert_equal([p["payment_id"] for p in sender.listpayjoins()], [payment_id])
            finally:
                node.setnetworkactive(True)

            not_sent_id = self.test_not_sent(sender, request)

            self.log.info("A deadline and cancellation retain exposure until explicit fallback")
            deadline_request = {**request, "timeout": ceil(3 * self.options.timeout_factor), "request_id": "deadline"}
            deadline_id = sender.sendpayjoin(**deadline_request)["payment_id"]
            self.wait_until(lambda: sender.getpayjoin(deadline_id).get("problem", {}).get("code") == "deadline")
            expired = sender.getpayjoin(deadline_id)
            assert_equal(expired["possibly_exposed"], True)
            assert_equal(expired["reservations"]["owned"], True)
            assert "selected" not in expired
            assert_equal(node.getrawmempool(), [])
            cancelled = sender.cancelpayjoin(deadline_id)
            assert_equal(cancelled["result"], "completed")
            assert_equal(cancelled["payment"]["reservations"]["owned"], True)
            assert_equal(node.getrawmempool(), [])
            fallback = sender.publishpayjoinfallback(deadline_id)
            assert_equal(fallback["result"], "completed")
            fallback_txid = fallback["payment"]["original"]["txid"]
            assert_equal(fallback["payment"]["selected"]["txid"], fallback_txid)
            assert fallback_txid in node.getrawmempool()
            assert_equal(sender.retrypayjoin(deadline_id, "retry_publication")["result"], "completed")
            self.generatetoaddress(node, 1, sender.getnewaddress())
            assert_equal(sender.getpayjoin(deadline_id)["phase"], "confirmed")
            assert_equal(sender.listlockunspent(), [])

            self.log.info("Unload/reload releases the managed wallet and starts a new identifier scope")
            node.unloadwallet("sender")
            node.loadwallet("sender")
            sender = node.get_wallet_rpc("sender")
            assert_equal(sender.listpayjoins(), [])
            for old_id in [payment_id, not_sent_id, deadline_id]:
                assert_raises_rpc_error(-8, "Unknown", sender.getpayjoin, old_id)
            reloaded_id = self.test_not_sent(sender, request)
            assert reloaded_id != not_sent_id


if __name__ == '__main__':
    PayjoinTest(__file__).main()
