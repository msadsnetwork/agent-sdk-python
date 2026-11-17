import json, os, sys
sys.path.insert(0, os.path.dirname(__file__))
from msads_agent import sign, AgentExchange
_d = os.path.dirname(os.path.abspath(__file__))
_f = os.path.join(_d, "test_vectors.json")
v = json.load(open(_f if os.path.exists(_f) else os.path.join(_d, "..", "test_vectors.json")))
for t in v["vectors"]:
    assert sign(t["secret"], t["timestamp"], t["nonce"], t["method"], t["path"], t["body"]) == t["signature"], t
assert len(AgentExchange.proof_hash("ORDER-1")) == 64
print("python sdk: %d signature vectors OK" % len(v["vectors"]))
