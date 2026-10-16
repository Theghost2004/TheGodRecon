"""Compatibility entry point for the shared verified installer."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from reconmap.installer import *  # Existing import-based installer clients remain supported.

if __name__ == '__main__':
    main()
