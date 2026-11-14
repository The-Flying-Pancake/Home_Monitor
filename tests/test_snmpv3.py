"""SNMPv3 (snmpv3.py): keys from the RFC's own test values, and whole requests against a small v3 agent
that signs, encrypts and refuses like a real one (unknown user, wrong password, clock window)."""

import dataclasses
import socket
import threading
import time
import unittest
import unittest.mock

from tests import _env  # noqa: F401
from tests.helpers import request, start_api_server

import database
import poller
import snmpv3

ENGINE = bytes.fromhex("80001f8880") + b"test-engine"
SYS_DESCR, SYS_OBJECT, SYS_NAME = "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"


def octets(text):
    return poller._tlv(poller.TAG_OCTET_STRING, text.encode())


def counter(n):
    return poller._tlv(poller.TAG_COUNTER32, n.to_bytes(4, "big"))


class Agent:
    """A v3 agent on 127.0.0.1 for one user. Answers GET and GETBULK from a fixed table."""

    def __init__(self, cred, values=None, boots=7):
        self.cred, self.boots, self.t0 = cred, boots, time.monotonic()
        self.values = values or {SYS_DESCR: octets("Test agent v3"), SYS_NAME: octets("agent-v3"),
                                 SYS_OBJECT: poller._tlv(poller.TAG_OID, poller._encode_oid("1.3.6.1.4.1.8072.3.2.10")[2:]),
                                 IF_DESCR + ".1": octets("eth0"), IF_DESCR + ".2": octets("eth1")}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.requests = 0
        self.stop = False
        threading.Thread(target=self.serve, daemon=True).start()

    def etime(self):
        return 1000 + int(time.monotonic() - self.t0)

    def close(self):
        self.stop = True
        self.sock.close()

    def report(self, msg_id, oid, signed=False):
        cred = dataclasses.replace(self.cred, level="authNoPriv") if signed else None
        return snmpv3.build(msg_id, cred, ENGINE, self.boots, self.etime(),
                            snmpv3.pdu(snmpv3.PDU_REPORT, 0, [], values=[(oid, counter(1))]), reportable=False)

    def answer(self, data):
        m = snmpv3.parse(data)
        if not m.user:
            return self.report(m.msg_id, snmpv3.UNKNOWN_ENGINE_ID)
        if m.user.decode() != self.cred.user:
            return self.report(m.msg_id, "1.3.6.1.6.3.15.1.1.3.0")
        keys = snmpv3.keys_for(self.cred, ENGINE)
        try:
            scoped = snmpv3.open_scoped(data, m, self.cred, keys)
        except snmpv3.V3Error:
            return self.report(m.msg_id, "1.3.6.1.6.3.15.1.1.5.0")
        if m.boots != self.boots or abs(m.time - self.etime()) > snmpv3.TIME_WINDOW:
            return self.report(m.msg_id, snmpv3.NOT_IN_TIME_WINDOW, signed=True)
        try:
            tag, rid, _, varbinds = snmpv3.parse_pdu(scoped)
        except (ValueError, IndexError):
            return self.report(m.msg_id, "1.3.6.1.6.3.15.1.1.6.0")
        self.requests += 1
        key = poller._oid_key
        if tag == poller.PDU_GETBULK:
            cursor = varbinds[0][0]
            after = sorted((o for o in self.values if key(o) > key(cursor)), key=key)[:10]
            out = [(o, self.values[o]) for o in after] or [(cursor, b"\x82\x00")]
        else:
            out = [(o, self.values.get(o, b"\x80\x00")) for o, _ in varbinds]
        return snmpv3.build(m.msg_id, self.cred, ENGINE, self.boots, self.etime(),
                            snmpv3.pdu(poller.PDU_RESPONSE, rid, [], values=out), reportable=False, keys=keys)

    def serve(self):
        while not self.stop:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                return
            try:
                reply = self.answer(data)
            except Exception:           # a broken request gets no answer, as on a real agent
                continue
            try:
                self.sock.sendto(reply, addr)
            except OSError:
                return


PRIV = snmpv3.Credential(user="monitor", level="authPriv", auth_protocol="SHA", auth_password="auth-pass-123",
                         priv_protocol="AES", priv_password="priv-pass-456")
AUTH256 = snmpv3.Credential(user="monitor", level="authNoPriv", auth_protocol="SHA-256", auth_password="auth-pass-256")


class KeyTests(unittest.TestCase):
    def test_rfc3414_sha_key_values(self):
        """RFC 3414 appendix A.3.2: password maplesyrup, engine ID 00...02."""
        ku = snmpv3.password_to_key("maplesyrup", "SHA")
        self.assertEqual(ku.hex(), "9fb5cc0381497b3793528939ff788d5d79145211")
        kul = snmpv3.localize_key(ku, bytes.fromhex("000000000000000000000002"), "SHA")
        self.assertEqual(kul.hex(), "6695febc9288e36282235fc7151f128497b38f3f")

    def test_keys_differ_per_engine_and_protocol(self):
        a = snmpv3.keys_for(PRIV, b"engine-a")
        b = snmpv3.keys_for(PRIV, b"engine-b")
        self.assertNotEqual(a, b)
        self.assertEqual(len(a[0]), 20)
        self.assertEqual(len(a[1]), 16)
        self.assertEqual(len(snmpv3.keys_for(AUTH256, b"engine-a")[0]), 32)
        self.assertEqual(snmpv3.keys_for(AUTH256, b"engine-a")[1], b"")

    def test_credential_checks_and_never_shows_passwords(self):
        self.assertEqual(PRIV.problems(), [])
        short = dataclasses.replace(PRIV, auth_password="short")
        self.assertIn("at least 8", short.problems()[0])
        self.assertTrue(dataclasses.replace(PRIV, auth_protocol="MD5").problems())
        self.assertTrue(dataclasses.replace(PRIV, level="noAuthNoPriv").problems())
        self.assertTrue(dataclasses.replace(PRIV, user="").problems())
        self.assertNotIn("auth-pass-123", repr(PRIV))
        self.assertNotIn("priv-pass-456", repr(PRIV))


class RequestTests(unittest.TestCase):
    def agent(self, cred):
        a = Agent(cred)
        self.addCleanup(a.close)
        snmpv3.forget("127.0.0.1", a.port)
        return a

    def test_auth_priv_sha_aes(self):
        a = self.agent(PRIV)
        got = poller.snmp_get_many("127.0.0.1", [SYS_DESCR, SYS_NAME], PRIV, a.port, 1.0, 1)
        self.assertEqual(got, {SYS_DESCR: "Test agent v3", SYS_NAME: "agent-v3"})
        self.assertEqual(snmpv3.last_error("127.0.0.1"), "")
        # The engine is remembered: the next request needs no discovery.
        self.assertEqual(poller.snmp_get("127.0.0.1", SYS_NAME, PRIV, a.port, 1.0, 0), "agent-v3")

    def test_auth_no_priv_sha256_and_walk(self):
        a = self.agent(AUTH256)
        self.assertEqual(poller.snmp_get("127.0.0.1", SYS_DESCR, AUTH256, a.port, 1.0, 1), "Test agent v3")
        self.assertEqual(poller.snmp_walk("127.0.0.1", IF_DESCR, AUTH256, a.port, 1.0, 1), {"1": "eth0", "2": "eth1"})

    def test_the_values_are_encrypted_on_the_wire(self):
        a = self.agent(PRIV)
        sent = []
        real = socket.socket.send

        def spy(sock, data, *args):
            sent.append(data)
            return real(sock, data, *args)
        with unittest.mock.patch.object(socket.socket, "send", spy):
            poller.snmp_get("127.0.0.1", SYS_DESCR, PRIV, a.port, 1.0, 1)
        self.assertTrue(sent)
        # The OID asked for is inside the encrypted part: not readable in any request after discovery.
        self.assertFalse(any(poller._encode_oid(SYS_DESCR) in d for d in sent[1:]))
        self.assertFalse(any(b"priv-pass" in d or b"auth-pass" in d for d in sent))

    def test_refusals_in_plain_words(self):
        a = self.agent(PRIV)
        wrong = dataclasses.replace(PRIV, auth_password="not-the-password")
        self.assertIsNone(poller.snmp_get("127.0.0.1", SYS_DESCR, wrong, a.port, 1.0, 0))
        self.assertIn("Wrong authentication password", snmpv3.last_error("127.0.0.1"))
        stranger = dataclasses.replace(PRIV, user="stranger")
        self.assertIsNone(poller.snmp_get("127.0.0.1", SYS_DESCR, stranger, a.port, 1.0, 0))
        self.assertIn("does not know this user", snmpv3.last_error("127.0.0.1"))
        bad_priv = dataclasses.replace(PRIV, priv_password="not-the-privacy")
        self.assertIsNone(poller.snmp_get("127.0.0.1", SYS_DESCR, bad_priv, a.port, 1.0, 0))
        self.assertTrue(snmpv3.last_error("127.0.0.1"))

    def test_clock_window_is_caught_up(self):
        a = self.agent(PRIV)
        self.assertEqual(poller.snmp_get("127.0.0.1", SYS_NAME, PRIV, a.port, 1.0, 0), "agent-v3")
        with snmpv3._LOCK:
            snmpv3._ENGINES[("127.0.0.1", a.port)]["time"] -= 5000      # as after a long sleep or a restart
        self.assertEqual(poller.snmp_get("127.0.0.1", SYS_NAME, PRIV, a.port, 1.0, 0), "agent-v3")

    def test_no_answer(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            self.assertIsNone(poller.snmp_get("127.0.0.1", SYS_DESCR, PRIV, port, 0.3, 0))
        self.assertIn("No answer", snmpv3.last_error("127.0.0.1"))


class DeviceSettingsTests(unittest.TestCase):
    """Add and Edit device with v3: the passwords are stored sealed, shown only as set, kept when left blank."""

    @classmethod
    def setUpClass(cls):
        start_api_server()

    def test_add_edit_and_test_connection(self):
        a = Agent(PRIV)
        self.addCleanup(a.close)
        body = {"hostname": "v3-device", "ip_address": "198.51.100.231", "profile_id": "generic_device",
                "snmp_version": "v3", "snmp_v3": {"user": "monitor", "level": "authPriv", "auth_protocol": "SHA",
                                                  "auth_password": "auth-pass-123", "priv_protocol": "AES",
                                                  "priv_password": "priv-pass-456"}}
        bad = dict(body, snmp_v3=dict(body["snmp_v3"], auth_password="short"))
        self.assertEqual(request("POST", "/api/devices", bad)[0], 400)
        status, res, _ = request("POST", "/api/devices", body)
        self.assertEqual(status, 201, res)
        dev_id = res["device_id"]
        self.addCleanup(database.delete_device, dev_id)
        stored = database.get_device(dev_id)
        self.assertEqual(stored["snmp_version"], "v3")
        self.assertEqual(stored["snmp_v3"]["priv_password"], "priv-pass-456")
        with database.get_connection() as conn:
            raw = conn.execute("SELECT snmp_v3 FROM devices WHERE id = ?;", (dev_id,)).fetchone()[0]
        self.assertNotIn("priv-pass-456", raw)
        self.assertNotIn("monitor", raw)
        shown = request("GET", f"/api/devices/{dev_id}")[1]
        text = repr(shown)
        self.assertNotIn("auth-pass-123", text)
        self.assertNotIn("priv-pass-456", text)
        listed = repr(request("GET", "/api/devices")[1])
        self.assertNotIn("priv-pass-456", listed)
        # Edit with the passwords left blank: they are kept. The target polls with them.
        edit = dict(body, snmp_v3=dict(body["snmp_v3"], auth_password="", priv_password="", user="monitor"))
        self.assertEqual(request("PUT", f"/api/devices/{dev_id}", edit)[0], 200)
        target = poller.snmp_target(database.get_device(dev_id))
        self.assertEqual(target.priv_password, "priv-pass-456")
        # Test connection against the agent, the passwords taken from the device being edited.
        probe = request("POST", "/api/devices/probe", {"ip_address": "127.0.0.1", "port": a.port, "snmp_version": "v3",
                                                       "device_id": dev_id, "snmp_v3": edit["snmp_v3"]})[1]
        self.assertTrue(probe.get("snmp_active"), probe)
        self.assertEqual(probe["sys_name"], "agent-v3")
        wrong = dict(edit["snmp_v3"], auth_password="wrong-password")
        probe = request("POST", "/api/devices/probe", {"ip_address": "127.0.0.1", "port": a.port, "snmp_version": "v3",
                                                       "device_id": dev_id, "snmp_v3": wrong})[1]
        self.assertFalse(probe.get("snmp_active"))
        self.assertIn("Wrong authentication password", probe.get("snmp_error", ""))
        # Back to v2c: the v3 settings go, the community stays.
        self.assertEqual(request("PUT", f"/api/devices/{dev_id}", dict(body, snmp_version="v2c"))[0], 200)
        back = database.get_device(dev_id)
        self.assertEqual((back["snmp_version"], back["snmp_v3"]), ("v2c", {}))
        self.assertIsInstance(poller.snmp_target(back), str)



class SnmpCheckTests(unittest.TestCase):
    """The SNMP check on a device's page: what is wrong, in plain words, against a v3 agent."""

    @classmethod
    def setUpClass(cls):
        start_api_server()

    def device(self, port, auth_protocol="SHA"):
        body = {"hostname": f"check-{port}-{auth_protocol}", "ip_address": "127.0.0.1", "profile_id": "generic_device",
                "snmp_port": port, "snmp_version": "v3",
                "snmp_v3": {"user": "monitor", "level": "authPriv", "auth_protocol": auth_protocol,
                            "auth_password": "auth-pass-123", "priv_protocol": "AES", "priv_password": "priv-pass-456"}}
        status, res, _ = request("POST", "/api/devices", body)
        self.assertEqual(status, 201, res)
        self.addCleanup(database.delete_device, res["device_id"])
        return res["device_id"]

    def check(self, dev_id):
        status, res, _ = request("POST", f"/api/devices/{dev_id}/snmp-check", {})
        self.assertEqual(status, 200, res)
        return res

    def test_all_right(self):
        a = Agent(PRIV)
        self.addCleanup(a.close)
        r = self.check(self.device(a.port))
        self.assertTrue(r["ok"], r)
        self.assertEqual([s["step"] for s in r["steps"]][1:], ["SNMPv3 answer", "User and password", "Values"])
        self.assertIn("2 network interfaces", r["steps"][-1]["detail"])

    def test_device_set_to_md5_is_named(self):
        a = Agent(dataclasses.replace(PRIV, auth_protocol="MD5", level="authNoPriv", priv_password=""))
        self.addCleanup(a.close)
        r = self.check(self.device(a.port))
        self.assertFalse(r["ok"])
        self.assertIn("The device is set to MD5.", [s["detail"] for s in r["steps"]])
        self.assertIn("choose SHA", r["advice"])
        self.assertNotIn("auth-pass-123", repr(r))
        # MD5 is recognised, never accepted as a device's setting.
        bad = {"hostname": "md5", "ip_address": "198.51.100.240", "profile_id": "generic_device", "snmp_version": "v3",
               "snmp_v3": {"user": "monitor", "level": "authNoPriv", "auth_protocol": "MD5", "auth_password": "auth-pass-123"}}
        self.assertEqual(request("POST", "/api/devices", bad)[0], 400)

    def test_other_protocol_and_privacy_advice(self):
        a = Agent(dataclasses.replace(PRIV, auth_protocol="SHA-256", level="authNoPriv", priv_password=""))
        self.addCleanup(a.close)
        dev = self.device(a.port)
        r = self.check(dev)
        self.assertIn("The device uses SHA-256, not SHA.", [s["detail"] for s in r["steps"]])
        self.assertIn("choose SHA-256", r["advice"])


if __name__ == "__main__":
    unittest.main()
