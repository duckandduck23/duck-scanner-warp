"""Entry point for the packaged app (Duck-Scanner.exe)."""
import sys

import warp_web


def run():
    try:
        warp_web.main()
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        print(f"\nDuck Scanner crashed: {e}")
        if getattr(sys, "frozen", False):
            input("Press Enter to close...")
        raise


if __name__ == "__main__":
    run()
