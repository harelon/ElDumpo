import argparse
import json
import os
import subprocess
from binascii import hexlify

dev_null = open('/dev/null', 'w')
replacement_dict = {
    "-": "_",
    "/": "_",
    " ": "_",
    ".": "_",
    "+": "p"
}
message_alignment = 60


class SegmentInfo():
    def __init__(self, name, base, end):
        self.name = name
        self.base = base
        self.end = end

        self.symbols = dict()


def parse_proc_maps(proc_maps):
    # create a dict between segments and their base
    segment_to_addrs = dict()
    for line in proc_maps.split("\n"):
        base_addr = line[:line.find("-")]
        end_addr = line[line.find("-") + 1: line.find(" ")]
        segment_name = " ".join(line.split(" ")[5:]).strip()
        if segment_name == "":
            continue
        if segment_name not in segment_to_addrs.keys():
            segment_to_addrs[segment_name] = (
                int(base_addr, 0x10),
                int(end_addr, 0x10)
                )
        else:
            segment_to_addrs[segment_name] = (
                segment_to_addrs[segment_name][0],
                int(end_addr, 0x10)
                )

    Infos = list()
    for name, (base, end) in segment_to_addrs.items():
        Infos.append(SegmentInfo(name, base, end))
    return Infos


def parse_nm_output(nm_output):
    # read the output of nm into a dictionary
    addresess_to_symbols = dict()
    for line in nm_output.split("\n"):
        if not line or line[0] == " ":
            continue
        addr, _, symbol_name = line.split(" ")
        addresess_to_symbols[int(addr, 0x10)] = symbol_name
    return addresess_to_symbols


def main():
    parser = argparse.ArgumentParser(
        description="Create a dump file + symbols file"
        )
    parser.add_argument(
        "-a",
        "--auto",
        action="store_true",
        help="automatically download symbols for loaded modules"
        )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-p", "--pid", type=int, help="pid of the process you want to dump"
        )
    group.add_argument(
        "-n", "--name", type=str, help="name of the process you want to dump"
        )
    args = parser.parse_args()
    pid = str(args.pid)
    if args.name:
        try:
            pid = subprocess.check_output(
                ["pidof", "-s", args.name], stderr=dev_null
                ).decode("ascii").strip()
        except subprocess.CalledProcessError:
            print(f'No running process named "{args.name}"')
            exit(-1)

    proc_maps = f"/proc/{pid}/maps"
    if not os.path.exists(proc_maps):
        print(f"No process with pid {pid}")
        exit(-1)

    maps_content = None
    with open(proc_maps, "r") as maps:
        maps_content = maps.read()

    print("Creating dump")
    # set the filter to dump everything, else we get a really bad dump
    with open(f"/proc/{pid}/coredump_filter", 'r+') as f:
        prev_state = hex(int(f.read(), 0x10))
        f.write("0xff")
    # get a gcore by pid or proc name
    subprocess.run(["gcore", pid], stdout=dev_null, stderr=dev_null)
    with open(f"/proc/{pid}/coredump_filter", 'w') as f:
        f.write(prev_state)

    print("Parsing proc maps")
    # read proc maps and parse them
    files_to_bases = parse_proc_maps(maps_content)

    core_info = dict()
    # create a json matching symbols and their addresses using nm
    print("Adding symbols from files")
    if args.auto:
        print("Downloading available symbols this process may take some time...")
    symbol_count = 0
    failed_debug_symbols = list()
    succeeded_debug_symbols = list()
    for info in files_to_bases:
        is_elf = True
        # read the build id using objcopy
        try:
            # dump the contents of the buildid section to stdout and read it
            buildid_hex = subprocess.check_output(
                [
                    "objcopy",
                    info.name,
                    "/dev/null",
                    "--dump-section",
                    ".note.gnu.build-id=/dev/stdout"
                ],
                stderr=dev_null)[16:]
        except subprocess.CalledProcessError:
            # we are trying to get a symbol from a file which is not an elf
            is_elf = False

        section_name = info.name.split("/")[-1]
        normalized_name = section_name
        for target, strip in replacement_dict.items():
            normalized_name = normalized_name.replace(target, strip)

        if is_elf:
            # try to find if there are debug files and read their symbols
            b_id = hexlify(buildid_hex).decode("ascii")
            dbg_info = f"/usr/lib/debug/.build-id/{b_id[:2]}/{b_id[2:]}.debug"
            symboled_file = info.name
            if os.path.exists(dbg_info):
                symboled_file = dbg_info
            # if auto is selected try to download the so's debug symbols
            elif args.auto:
                try:
                    # get the package name of the debug symbols
                    library_name = subprocess.check_output(
                        [
                            "grep-aptavail",
                            "--no-field-names",
                            "--show-field",
                            "Package",
                            "--field",
                            "Build-IDs",
                            "--pattern",
                            b_id
                        ]
                    ).decode("ascii").strip()
                    message = f"Downloading {library_name}"
                    message += " " * (message_alignment - len(message))
                    print(message, end="")
                    # try downloading the debug symbols library
                    try:
                        subprocess.run(
                            [
                                "apt",
                                "install",
                                library_name,
                            ],
                            check=True,
                            stdout=dev_null,
                            stderr=dev_null
                        )
                        print("Succeeded")
                        succeeded_debug_symbols.append(library_name)
                        # if we succeeded take symbols from the debug library
                        symboled_file = dbg_info
                    except subprocess.CalledProcessError:
                        print("Failed")
                        failed_debug_symbols.append(library_name)
                except subprocess.CalledProcessError:
                    pass

            symbol_output = subprocess.check_output(
                ["nm", "-D", symboled_file],
                stderr=dev_null
                ).decode("ascii")
            symbol_output += subprocess.check_output(
                ["nm", symboled_file],
                stderr=dev_null
                ).decode("ascii")
            symbols_info = parse_nm_output(symbol_output)
            symbol_count = symbol_count + len(symbols_info)
            for symbol_addr, symbol_name in symbols_info.items():
                info.symbols[info.base + symbol_addr] = \
                     normalized_name + "__" + symbol_name

        del(info.name)
        core_info[section_name] = info.__dict__

    print(f"Found {symbol_count:,} symbols")
    print("Writing Json")
    with open(f"core.{pid}.symbols", "w") as f:
        f.write(json.dumps(core_info))

    if len(failed_debug_symbols) or len(succeeded_debug_symbols):
        log_file = f"library_status-{pid}.log"
        with open(log_file, "w") as f:
            if len(failed_debug_symbols):
                f.write("Failed libraries summary:\n")
                for library in failed_debug_symbols:
                    f.write(f"\t{library}\n")
            if len(succeeded_debug_symbols):
                f.write("Succeeded libraries summary:\n")
                for library in succeeded_debug_symbols:
                    f.write(f"\t{library}\n")
            print(f"library log output in file {log_file}")


if __name__ == "__main__":
    main()
