import sys

from . import __version__


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--version"]:
        print(f"loopkeeper {__version__}")
        return 0
    # Minimal CLI surface for bootstrap; full command set lands in later tasks.
    print(f"loopkeeper {__version__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
