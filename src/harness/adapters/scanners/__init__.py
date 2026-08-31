"""Bundled scanner adapters.

Nothing is re-exported here. Exporting one of the seven — which is what this
package did — made a partial public surface, and the choice of which one was
arbitrary. Import a scanner from its own module when a direct reference is
needed; `from_yaml()` builds them from the factory table in core/wiring.py,
which is the whole set SHAI Core has.
"""
