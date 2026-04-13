import sys
sys.path.append('c:\\Anti\\DNS PROJECT')
from threat_engine import ThreatEngine

engine = ThreatEngine()
# Analyze a masked domain
result = engine.analyze('http://gla.ac.in@10.33.2.1/login')
print(result['domain'])
print(result['reason'])
