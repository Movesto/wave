"""Neuro-symbolic vulnerability agent — orchestrator (Phase 1 build).

The model TRANSLATES, deterministic tools PROVE. Fresh module (distinct from the legacy
single-shot scanner/); reuses only validated *components* (scanner/flag.py detection, the
Phase-0 sink hooks) as libraries. Built on what Phase 0 proved: prove-first dynamic loop +
per-driver instrumented-sink / differential oracles.
"""
__version__ = "0.1.0"
