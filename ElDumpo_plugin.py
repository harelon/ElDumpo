import ida_idaapi
import ida_nalt
import ida_loader
import os
import ida_kernwin
import json
import ida_segment
import ida_name


class ElDumpo(ida_idaapi.plugin_t):
    flags = 0
    wanted_name = "ElDumpo"

    def init(self):
        self.symbols = f"{ida_nalt.get_input_file_path()}.symbols"
        if "(Core file)" not in ida_loader.get_file_type_name():
            return ida_idaapi.PLUGIN_SKIP

        if not os.path.exists(self.symbols):
            print("Create a dump with symbols using the dumper if you can")
            return ida_idaapi.PLUGIN_SKIP

        return ida_idaapi.PLUGIN_KEEP

    def run(self, _):
        ida_kernwin.process_ui_action("UndoToggle")

        try:
            core_info = None
            with open(self.symbols, "r") as f:
                core_info = json.loads(f.read())

            used_names = dict()
            current_seg = ida_segment.get_first_seg()
            inf = ida_idaapi.get_inf_structure()
            addressing = 2 if inf.is_64bit() else 1

            unknowning_list = list()

            for segment_name, segement in core_info.items():
                segement_base = int(segement["base"])
                segement_end = int(segement["end"])

                # we are iterating in order,
                # if the current so isn't mapped to this segment
                # then no one is mapped to it
                while current_seg.start_ea < segement_base:
                    current_seg = ida_segment.get_next_seg(
                        current_seg.start_ea
                        )

                # if there was no ida segment that contained the segment
                # it means that we skipped it
                if segement_base < current_seg.start_ea:
                    ida_segment.add_segm(
                        0,
                        segement_base,
                        segement_end,
                        segment_name,
                        "CODE",
                        ida_segment.ADDSEG_QUIET
                        )
                    created_segment = ida_segment.getseg(segement_base)
                    ida_segment.set_segm_addressing(
                        created_segment,
                        addressing
                        )
                    unknowning_list.append(created_segment.start_ea)
                    continue

                # iterate ida segments containing the segment
                # add ones that are missing
                while current_seg and \
                        segement_base <= current_seg.start_ea < segement_end:
                    last_seg = current_seg
                    current_seg = ida_segment.get_next_seg(
                        current_seg.start_ea
                        )
                    # check segments, change their name correctly
                    if ida_segment.get_segm_name(last_seg) == "load":
                        ida_segment.set_segm_name(last_seg, segment_name)

                    # gcore skipped adding the segment
                    # we want to add it in ida to use its symbols
                    # add segments if they don't exist
                    if current_seg and \
                        current_seg.start_ea <= segement_end \
                            and last_seg.end_ea != current_seg.start_ea:
                        ida_segment.add_segm(
                            0,
                            last_seg.end_ea,
                            current_seg.start_ea,
                            segment_name,
                            "CODE",
                            ida_segment.ADDSEG_QUIET
                            )
                        created_segment = ida_segment.getseg(last_seg.end_ea)
                        ida_segment.set_segm_addressing(
                            created_segment,
                            addressing
                        )
                        unknowning_list.append(created_segment.start_ea)

                if "symbols" not in segement.keys():
                    continue

                for addr, name in segement["symbols"].items():
                    current_name = name
                    if current_name in used_names:
                        current_name = current_name + \
                            "_" + \
                            str(used_names[current_name])

                        used_names[name] += 1
                    else:
                        used_names[name] = 1

                    ida_name.set_name(int(addr), current_name)
        finally:
            ida_kernwin.process_ui_action("UndoToggle")

    def term(self):
        pass


def PLUGIN_ENTRY():
    return ElDumpo()
