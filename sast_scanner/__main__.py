"""Entry point: python -m sast_scanner"""
from .cli import main
import sys

sys.exit(main())
