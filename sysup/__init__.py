"""System Supe-Up — an AI PC monitor that explains freezes rather than graphing them.

The detection is local, deterministic and offline: `winapi` reads what the
Windows kernel knows about every thread's wait state, `collect` turns that into
rates, and `rules` decides what is wrong.  Only the explanation goes to a
model, and only after the findings are already settled — so a report is never
wrong because the model was.
"""

__version__ = "1.0.0"

__all__ = ["collect", "config", "diagnose", "knowledge", "llm", "report",
           "research", "rules", "sysinfo", "ui", "winapi"]
