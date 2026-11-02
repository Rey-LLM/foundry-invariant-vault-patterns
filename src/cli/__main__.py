"""Allow `python3 -m foundryguard` after installation."""
import sys

from .foundryguard import main

sys.exit(main())
