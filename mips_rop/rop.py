"""
rop.py: calculate rop gadgets contained in the executable sections of binaries
"""

from operator import itemgetter
from binaryninja import *
import re

INSTR_SIZE = 4
# This is a JALR in t9
# [ŦODO] Add jumps to other registers even if they are rare
_JUMP_INSTRS = {"jalr $t9": [b"\x03\x20\xf8\x09"], "jr $t9": [
    b"\x03\x20\x00\x08"], "jr $ra": [b"\x03\xe0\x00\x08"]}


class ROPSearch(BackgroundTaskThread):
    """
    class that assists in location rop gadgets in executable code segments
    """

    def __init__(self, bv: BinaryView):
        BackgroundTaskThread.__init__(self, "", True)
        self.bv = bv
        self.gadgets = {}
        self.progress = "[+] mips_rop: searching for rop gadgets"
        self.endianness = self.bv.perform_get_default_endianness()
        self.arch = self.bv.arch
        self.jump_instrs = _JUMP_INSTRS

    def run(self):
        """
        locate rop gadgets in executable sections of a binary
        """
        if not self.bv.executable:
            return

        # get instructions rather than sections
        instructions = [i for i in self.bv.instructions]
        gadgets = self._find_gadgets_in_data(instructions)
        if gadgets != {}:
            self._generate_output(gadgets, "rop gadgets")
            # _generate_html(self.view, gadgets, "rop gadgets")
        else:
            show_message_box(
                "mips_rop: gadget search", "could not find any rop gadgets"
            )
        self.progress = ""

    def _disas_all_instrs(self, start_addr, jump_addr: int) -> list[str]:
        """
        disassemble all instructions in chunk
        """
        instructions: list[str] = []
        curr_addr = start_addr
        while curr_addr < jump_addr:
            instr = self.bv.get_disassembly(curr_addr)
            if instr == "":  # bad addr
                return None
            instructions.append(instr)
            curr_addr += self.bv.get_instruction_length(curr_addr)
        # jump opcode was included in last instruction calculation
        if curr_addr != jump_addr:
            return None

        return instructions

    def _calculate_gadget_from_jump(self, gadgets: dict[int, (str, str)], jump_addr: int):
        """
        decrement index from jump ins and calculate gadgets
        """
        jump_instr = self.bv.get_disassembly(jump_addr)
        jump_addr += 4
        # [TODO] and $reg_dest, $reg_source, $reg_source is also a possible way load values
        # addiu comes from https://write.lain.faith/~/Haskal/mips-rop/
        t9_ctrl = [r"move +\$t9, ", r"addiu +\$t9, ",
                   r"or +\$t9, \$.., \$zero"]
        ra_ctrl = [r"lw +\$ra, "]
        for i in range(0, Settings().get_integer("ropsettings.depth")*INSTR_SIZE + 1):
            #  MIPS has jump delay slots, this means that the instruction
            # immediatly after the jump is executed with the jump
            instructions = self._disas_all_instrs(jump_addr - i, jump_addr + 4)
            if instructions is None:
                continue
            gadget_str = ""
            for instr in instructions:
                gadget_str += f"{instr} ; "

            # https://github.com/tacnetsol/ida/blob/master/plugins/mipsrop/mipsrop.py#LL373C58-L373C58
            control_reg = ""
            # [TODO] Search in reverse, in case the control passes through more moves
            if "$t9" in jump_instr:
                ctrl_arr = t9_ctrl
            elif "$ra":
                ctrl_arr = ra_ctrl
            else:
                print(f"Weird jump {gadget_str}")

            for ctrl in ctrl_arr:
                ctrl_idx = re.search(ctrl, gadget_str)
                if ctrl_idx:
                    ctrl_idx = ctrl_idx.end()
                    control_reg = gadget_str[ctrl_idx:gadget_str.find(
                        " ;", ctrl_idx)]
                    break

            if "$t9" in control_reg or "$ra" in control_reg:
                control_reg = ""

            if control_reg != "":
                gadget_rva = jump_addr - i - self.bv.start
                gadgets[gadget_rva] = (f"{gadget_str}", control_reg)
        return gadgets

    def _find_gadgets_in_data(
        self, insts: tuple[list[str], int]
    ) -> dict[int, (str, str)]:
        """
        find jump instructions and spawn a thread to calculate gadgets
        """
        gadgets: dict[int, (str, str)] = dict()
        for _, bytecodes in _JUMP_INSTRS.items():
            for bytecode in bytecodes:
                next_start = insts[0][1]
                next_jump_addr = 0
                while next_start < insts[-1][1]:
                    next_jump_addr = self.bv.find_next_data(
                        next_start, bytecode)
                    if next_jump_addr is None:
                        break

                    # TODO thread this?
                    gadgets = self._calculate_gadget_from_jump(
                        gadgets, next_jump_addr)
                    next_start = next_jump_addr + len(bytecode)
                    # [y[1] for y in ins].index(4199412)

        return gadgets

    def _generate_output(self, gadgets: dict[int, (str, str)], title: str):
        """
        display rop gadgets
        """
        markdown = f"rop gadgets found for {self.bv.file.filename}\n\n"
        body = ""
        stackfinder_gadgets = ""
        lia0_gadets = ""
        registers_gadgets = ""
        system_gadgets = ""
        double_jump_gadgets = ""
        all_gadgets = ""
        found = []
        gadgets = dict(sorted(gadgets.items()))
        # print(gadgets)
        for addr, gadget in sorted(gadgets.items(), key=itemgetter(1)):
            if gadget not in found:
                gadget_str = " ".join(gadget[0].split())
                addr = addr + self.bv.start  # make sure addrs are correct
                control_reg = f"Control reg: <span style='color: green;'>{gadget[1]}</span>"
                f_gadget_str = f"[{addr:#016x}](binaryninja://?expr={addr:08x}) \t{control_reg:85} \t{gadget_str}\n\n"
                all_gadgets += f_gadget_str

                # stackfinder
                if re.search(r"addiu \$.., \$sp", f_gadget_str):
                    stackfinder_gadgets += f_gadget_str
                # lia0
                if "li $a0" in f_gadget_str:
                    lia0_gadets += f_gadget_str
                # registers
                if re.search(r"lw \$.., 0x[0-9a-z]{0,4}\(\$sp", f_gadget_str):
                    registers_gadgets += f_gadget_str
                # system
                if "addiu $a0, $sp" in f_gadget_str:
                    system_gadgets += f_gadget_str
                # double jumps
                if re.search(r"(jr|jalr).+(jr|jalr)", f_gadget_str):
                    double_jump_gadgets += f_gadget_str
                # tails?
                found.append(gadget)

        markdown += f"[+] found {len(found)} gadgets\n***\n"

        markdown += "[+] stackfinder gadgets\n\n"
        markdown += stackfinder_gadgets
        markdown += "***\n\n"

        markdown += "[+] lia0 gadgets\n\n"
        markdown += lia0_gadets
        markdown += "***\n\n"

        markdown += "[+] registers gadgets\n\n"
        markdown += registers_gadgets
        markdown += "***\n\n"

        markdown += "[+] system gadgets\n\n"
        markdown += system_gadgets
        markdown += "***\n\n"

        markdown += "[+] double jump gadgets\n\n"
        markdown += double_jump_gadgets
        markdown += "***\n\n"

        markdown += "[+] all gadgets\n\n"
        body += all_gadgets

        markdown += body
        self.bv.show_markdown_report(title, markdown)
