#!/usr/bin/env python3
"""Assert WHICH ADD-ON FILE ZAP ACTUALLY LOADS -- at image build time, and at runtime.

*** THIS EXISTS BECAUSE A LAYER THAT INSTALLS A FILE PROVES NOTHING ABOUT WHICH FILE LOADS. ***

Build #20 measured its entire GraphQL go/no-go (56 checks) against `graphql-alpha-0.33.0`. The
IMAGE ships 0.29.0. The 0.33.0 was a RUNTIME AUTO-UPDATE sitting in one container's writable
layer at `/root/.ZAP/plugin/`, and ZAP prefers `$HOME/.ZAP/plugin` to the system directory. So
every one of those 56 measurements was against an implementation the image does not build, and
nothing in the build said so. Recreating the container would have silently reverted the engine
under a proof that had already been written down as passing.

It is `api.disablekey` one level worse. That was a daemon persisting a SETTING; this is a daemon
persisting an entire ADD-ON VERSION -- a different implementation of the thing under test.

*** THE ASSERTION IS `installedAddons`, NOT A DIRECTORY LISTING, AND THAT IS THE WHOLE POINT. ***
`autoupdate/view/installedAddons/` reports a `file` field: the ABSOLUTE PATH ZAP RESOLVED AND
LOADED. Listing `/usr/share/zaproxy/plugin/` would have passed happily in the exact container
where the drift lived, because the 0.29.0 file really was there -- ZAP was simply ignoring it.
Asking the daemon which file it loaded is the only question whose answer cannot be shadowed.

*** AND IT EARNED ITS KEEP ON THE FIRST RUN: AN ADD-ON VERSION IS A DEPENDENCY CLOSURE, NOT A
    FILE. *** Dropping `graphql-alpha-0.33.0.zap` into the system plugin directory and deleting
0.29.0 produced a ZAP with NO GraphQL add-on loaded AT ALL -- not an error, not a warning, not a
line in the log: simply absent from `installedAddons`. 0.33.0's manifest requires
`commonlib >= 1.40.0 & < 2.0.0` and this image shipped **1.39.0**, so ZAP declined it in silence.
The 0.33.0 in the drifted container had only ever worked because the SAME auto-update pass had
also lifted commonlib to 1.43.0 -- which is the concrete, load-bearing reason the drift is
described as 33 add-ons wide rather than one. A pin is a SET, and this checker takes a set.

An `ls`-based check would have shipped that broken image with a green build.

TWO MODES, because the question is worth asking in both places:

    --start            start a throwaway daemon, assert, kill it, and leave NO state behind.
                       This is the build-time mode. It runs with `api.disablekey=true` on
                       loopback inside the build container and then DELETES the ZAP home it
                       created, so no API key, no `disablekey=true` and no `dayLastChecked`
                       is ever baked into the image. Baking a key would put a shared secret in
                       every container from this image; baking `disablekey=true` is the exact
                       trap that made a previous ZAP measurement conditional on history.

    --port/--key       assert against a daemon that is ALREADY RUNNING. This is the runtime
                       mode an operator (or a proof script) uses to ask a live daemon what it
                       is really running, rather than reading the Dockerfile and assuming.

It prints every `graphql-*.zap` it can find on disk before it asserts anything, because "more
than one is present" is the condition that produced this bug and a reader needs to see it.

*** IT WARNS AND CONTINUES WHERE IT CAN, AND FAILS ONLY ON THE PINNED FACT. *** A second add-on
file on disk is reported loudly and is NOT by itself an error -- ZAP resolving the pinned one
anyway is a pass, and refusing there would be a prohibition this build is not allowed to add.
The single thing that fails is: the file ZAP loaded is not the file that was pinned.

ASCII only: the console this is read from is cp1252.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

#: Where the pinned add-on is installed by the Dockerfile. ZAP's own install tree, NOT a ZAP
#: home -- a home directory is writable at runtime and is precisely what drifted.
SYSTEM_PLUGIN_DIR = "/usr/share/zaproxy/plugin"

#: Every place a ZAP add-on can hide. `$HOME/.ZAP/plugin` WINS over the system directory, which
#: is why it is listed first: it is the shadow, not the fallback.
SEARCH_DIRS = (
    os.path.expanduser("~/.ZAP/plugin"),
    "/root/.ZAP/plugin",
    "/home/sandbox/.ZAP/plugin",
    SYSTEM_PLUGIN_DIR,
)


def same_path(a: str, b: str) -> bool:
    """Compare two paths as PATHS, not as strings.

    *** ZAP REPORTS `/usr/share/zaproxy/./plugin/graphql-alpha-0.33.0.zap`. *** With a `./` in
    the middle, because the value is assembled from its install root plus a relative plugin
    directory and never normalised. A literal `==` against the path this build installs to
    therefore fails on a PERFECTLY CORRECT PIN -- measured here before it could be mistaken for
    a real failure. An exact string compare on a path a program prints is a test of that
    program's string-building, not of which file is on disk.
    """
    return os.path.normpath(a) == os.path.normpath(b)


def found_on_disk(addon_id: str) -> list[str]:
    """Every `<addon_id>-*.zap` visible, in ZAP's own resolution order."""
    out: list[str] = []
    for d in SEARCH_DIRS:
        for path in sorted(glob.glob(os.path.join(d, f"{addon_id}-*.zap"))):
            if path not in out:
                out.append(path)
    return out


def api(port: int, key: str, path: str, timeout: int = 30) -> dict:
    url = f"http://127.0.0.1:{port}/JSON/{path}"
    req = urllib.request.Request(url, headers={"X-ZAP-API-Key": key})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - loopback, literal
        return json.loads(resp.read().decode("utf-8", "replace"))


def wait_for_api(port: int, key: str, seconds: int) -> str:
    """The daemon's version string once it answers, or "" if it never does."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            return str(api(port, key, "core/view/version/", timeout=5).get("version", ""))
        except (urllib.error.URLError, OSError, ValueError):
            time.sleep(2)
    return ""


def loaded_addon(port: int, key: str, addon_id: str) -> dict | None:
    """The record ZAP holds for ``addon_id`` -- including the FILE IT RESOLVED."""
    rows = api(port, key, "autoupdate/view/installedAddons/").get("installedAddons", [])
    for row in rows:
        if row.get("id") == addon_id:
            return row
    return None


def start_daemon(port: int, home: str) -> subprocess.Popen:
    """A throwaway daemon that leaves nothing behind.

    ``start.checkForUpdates=false`` is stated because the auto-update is the thing under test:
    a build-time assertion that let ZAP go and fetch a newer add-on would assert whatever the
    marketplace happened to hold that minute, which is not a pin -- it is the drift again with
    a build number on it. (ZAP files the add-on auto-update options under `start.`; the
    `<start><dayLastChecked>` element a drifted container writes is that same subsystem.)
    """
    env = dict(os.environ, HOME=home)
    return subprocess.Popen(
        ["zaproxy", "-daemon", "-host", "127.0.0.1", "-port", str(port),
         "-config", "api.disablekey=true",
         "-config", "start.checkForUpdates=false"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def stop_daemon(proc: subprocess.Popen) -> None:
    """Kill the JVM by PROCESS GROUP.

    `zaproxy` is a wrapper script that exec's `java`, so `proc` may be the wrapper and the JVM
    its child. `pkill -f zaproxy` is the wrong instrument twice over: it matches this script's
    own argv, and it would kill a daemon an operator started. Signalling the group this
    function itself created cannot reach anything it did not start.
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        proc.terminate()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            proc.kill()


def parse_pin(spec: str) -> tuple[str, str, str]:
    """``id:status:version`` -> the id, the version and the file ZAP must load.

    The STATUS is part of the spec because it is part of the filename ZAP resolves
    (`graphql-alpha-0.33.0.zap`, `commonlib-release-1.43.0.zap`) and it is not derivable from
    the id. Guessing `-alpha-` for everything is how the second pin in a set goes wrong quietly.
    """
    parts = spec.split(":")
    if len(parts) != 3 or not all(parts):
        raise argparse.ArgumentTypeError(
            f"--pin wants id:status:version (e.g. graphql:alpha:0.33.0), got {spec!r}")
    addon_id, status, version = parts
    return addon_id, version, os.path.join(
        SYSTEM_PLUGIN_DIR, f"{addon_id}-{status}-{version}.zap")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pin", action="append", required=True, metavar="id:status:version",
                    help="an add-on ZAP must load, e.g. graphql:alpha:0.33.0. Repeatable -- "
                         "a pin is a SET, because an add-on with an unmet dependency is not "
                         "loaded and not complained about.")
    ap.add_argument("--port", type=int, default=18790)
    ap.add_argument("--key", default="", help="API key of an already-running daemon")
    ap.add_argument("--start", action="store_true",
                    help="start a throwaway daemon and clean up after it (build-time mode)")
    ap.add_argument("--home", default="/tmp/zap-addon-check-home",
                    help="ZAP home for --start; DELETED afterwards")
    ap.add_argument("--wait", type=int, default=240)
    args = ap.parse_args()

    pins = [parse_pin(spec) for spec in args.pin]

    print("== ZAP add-on pin check ==")
    for addon_id, version, want_file in pins:
        print(f"   PIN {addon_id} {version} -> {want_file}")
        on_disk = found_on_disk(addon_id)
        for path in on_disk:
            print(f"       on disk: {path}")
        if not on_disk:
            print("       on disk: NONE")
        if len(on_disk) > 1:
            # WARN AND CONTINUE. More than one is how the drift happened, so it is worth
            # shouting about -- but ZAP resolving the pinned one anyway is a pass, and the
            # assertion below is what decides. Failing here would be a prohibition on a state
            # that may well be fine.
            print("       *** WARNING: MORE THAN ONE IS PRESENT. $HOME/.ZAP/plugin WINS over "
                  "the system directory -- which file ZAP loads is asserted below. ***")

    proc = None
    if args.start:
        shutil.rmtree(args.home, ignore_errors=True)
        os.makedirs(args.home, exist_ok=True)
        print(f"   starting a throwaway daemon on 127.0.0.1:{args.port} (HOME={args.home})")
        proc = start_daemon(args.port, args.home)

    try:
        ver = wait_for_api(args.port, args.key, args.wait)
        if not ver:
            print(f"   FAIL  no ZAP daemon answered on 127.0.0.1:{args.port} within "
                  f"{args.wait}s")
            return 1
        print(f"   ZAP {ver} answers")

        failed = 0
        for addon_id, version, want_file in pins:
            row = loaded_addon(args.port, args.key, addon_id)
            if row is None:
                # THE FAILURE MODE THIS CHECKER WAS WRITTEN FOR, and it is a SILENCE. ZAP does
                # not warn about an add-on whose dependencies are unmet; it simply does not load
                # it, and `installedAddons` does not mention it. So say out loud what "absent"
                # most often means, because the file being right there on disk makes it look
                # like anything BUT a dependency problem.
                print(f"   FAIL  ZAP loaded NO add-on with id={addon_id}")
                print(f"         The file may be present and still not load: an add-on whose "
                      f"declared dependencies are unmet is skipped SILENTLY.")
                print(f"         Read its ZapAddOn.xml <dependencies> and pin those too.")
                failed += 1
                continue

            got_version = str(row.get("version", ""))
            got_file = str(row.get("file", ""))
            print(f"   ZAP LOADED {addon_id}: version={got_version}  file={got_file}")
            if got_version != version:
                print(f"   FAIL  {addon_id} is {got_version}, pinned is {version}")
                failed += 1
            elif not same_path(got_file, want_file):
                print(f"   FAIL  ZAP loaded {got_file}")
                print(f"         the pin is  {want_file}")
                print("         a file in a ZAP HOME shadows the system directory -- that is "
                      "exactly the drift this check exists for")
                failed += 1

        # *** AND THE SAME QUESTION FOR EVERY OTHER ADD-ON IN THE IMAGE. ***
        # Pinning one add-on can UNLOAD another: bumping `commonlib` to satisfy `graphql` moves
        # a version every other add-on also depends on, and an add-on whose dependency range no
        # longer matches is dropped in the same silence that started this. Checking only the
        # pins would have found the GraphQL scanner and lost, say, the spider, with a green
        # build either way.
        #
        # The invariant is MEASURED, not assumed: on the image before this layer existed, all
        # 48 `.zap` files in the plugin directory appear in `installedAddons` -- so "every file
        # present is loaded" is a property this image genuinely had, and losing it is a real
        # regression rather than a rule invented to look strict.
        rows = api(args.port, args.key, "autoupdate/view/installedAddons/").get(
            "installedAddons", [])
        loaded_files = [str(r.get("file") or "") for r in rows]
        present = sorted(glob.glob(os.path.join(SYSTEM_PLUGIN_DIR, "*.zap")))
        unloaded = [p for p in present
                    if not any(same_path(p, f) for f in loaded_files)]
        print(f"   {len(rows)} add-ons loaded; {len(present)} .zap files in "
              f"{SYSTEM_PLUGIN_DIR}")
        if unloaded:
            print("   FAIL  present on disk and NOT loaded by ZAP "
                  "(almost always an unmet dependency, and ZAP says nothing):")
            for path in unloaded:
                print(f"           {os.path.basename(path)}")
            failed += len(unloaded)

        if failed:
            print(f"   {failed} problem(s); the pin is NOT satisfied")
            return 1
        print(f"   PASS  ZAP loads all {len(pins)} pinned add-ons from the image, "
              f"and every .zap present is loaded")
        return 0
    finally:
        if proc is not None:
            stop_daemon(proc)
            # The ZAP home this check created is DELETED. Anything left here ships in the image
            # and conditions every container built from it -- an API key ZAP mints on first
            # start, `api.disablekey`, `dayLastChecked`. A checker that persisted state would
            # be reproducing the bug it is here to catch.
            shutil.rmtree(args.home, ignore_errors=True)
            print(f"   (throwaway daemon stopped, {args.home} removed -- nothing persisted)")


if __name__ == "__main__":
    sys.exit(main())
