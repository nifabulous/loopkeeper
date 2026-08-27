import sys

from . import __version__


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--version"]:
        print(f"loopkeeper {__version__}")
        return 0
    from .cli import main as cli_main

    return cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
