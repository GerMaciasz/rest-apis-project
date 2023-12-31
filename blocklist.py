"""
blocklist.py
This file just contains the blocklist of the JWT tokens, It will be imported by app and the logout resource so that tokens
can be added to the block list when th user logs out.
"""

BLOCKLIST = set()