"""Bundled scanner adapters.

Scanners are resolved by name through the `harness.scanners` entry-point group
(see harness.adapters.discovery), so nothing is re-exported here. Exporting one
of the seven — which is what this package did — made a second, partial public
surface alongside the entry points, and the choice of which one was arbitrary.
Import a scanner from its own module when a direct reference is needed.
"""
