"""
Pytest configuration for ThreatLens AI.
Ensures project root is always in Python's module search path.
"""

import sys
import os

# Add threatlens-ai root directory to sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
