"""
firewall.py

PIPELINE STAGE 3a: Firewall Engine

    Traffic Analyzer -> [Firewall Engine] -> Threat Score
                              |
                    Incoming packet
                              |
                      Check firewall rules
                              |
                       Match found?
                     YES /        \\ NO
                  Action        Default policy

Checks a packet against simple IP / port / protocol rules and
returns a decision: "ALLOW" or "BLOCK". Rules are checked in order,
most specific first: IP rules, then protocol+port rules. If nothing
matches, the default policy applies.

Kept deliberately simple -- no rule priorities, no NAT, no stateful
tracking. That's the IDS/Threat Score/Response Engine's job later
in the pipeline.
"""

DEFAULT_POLICY = "ALLOW"  # falls back to this when no rule matches

# Each rule matches on whatever keys it defines; a missing key means
# "don't check this field". First matching rule wins.
RULES = [
    {"action": "BLOCK", "ip": "192.168.1.50"},      # example: known-bad test IP
    {"action": "BLOCK", "protocol": "TCP", "port": 23},   # Telnet - insecure, block it
    {"action": "ALLOW", "protocol": "TCP", "port": 443},  # HTTPS
    {"action": "ALLOW", "protocol": "TCP", "port": 22},   # SSH
]


class FirewallEngine:
    def __init__(self, rules=None, default_policy=None):
        self.rules = rules if rules is not None else list(RULES)
        self.default_policy = default_policy or DEFAULT_POLICY

    def check(self, packet) -> str:
        """Return 'ALLOW' or 'BLOCK' for this packet."""
        for rule in self.rules:
            if self._matches(rule, packet):
                return rule["action"]
        return self.default_policy

    @staticmethod
    def _matches(rule: dict, packet) -> bool:
        if "ip" in rule and rule["ip"] not in (packet.src_ip, packet.dst_ip):
            return False
        if "protocol" in rule and rule["protocol"] != packet.protocol:
            return False
        if "port" in rule and rule["port"] != packet.dst_port:
            return False
        return True

    def add_rule(self, action: str, ip: str = None, protocol: str = None, port: int = None):
        rule = {"action": action}
        if ip is not None:
            rule["ip"] = ip
        if protocol is not None:
            rule["protocol"] = protocol
        if port is not None:
            rule["port"] = port
        self.rules.insert(0, rule)  # newest rule takes priority
