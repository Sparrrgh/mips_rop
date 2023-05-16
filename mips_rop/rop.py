"""
rop.py: calculate rop gadgets contained in the executable sections of binaries
"""

from operator import itemgetter
from binaryninja import *
import re

# [TODO] Make configurable
DEPTH = 4
INSTR_SIZE = 4
# This is a JALR in t9
# [ŦODO] Add jumps to other registers even if they are rare
_RET_INSTRS = {"jalr t9": [b"\x03\x20\xf8\x09"], "jr t9" : [b"\x03\x20\x00\x08"]}

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
        self.ret_instrs = _RET_INSTRS

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

    def _disas_all_instrs(self, start_addr, ret_addr: int) -> list[str]:
        """
        disassemble all instructions in chunk
        """
        instructions: list[str] = []
        curr_addr = start_addr
        while curr_addr < ret_addr:
            instr = self.bv.get_disassembly(curr_addr)
            if instr == "":  # bad addr
                return None
            if instr in _RET_INSTRS.keys():  # exclude 2 rets
                return None
            instructions.append(instr)
            curr_addr += self.bv.get_instruction_length(curr_addr)
        # ret opcode was included in last instruction calculation
        if curr_addr != ret_addr:
            return None

        return instructions

    def _calculate_gadget_from_ret(self, gadgets: dict[int, (str, str)], ret_addr: int):
        """
        decrement index from ret ins and calculate gadgets
        """
        ret_addr += 4 
        for i in range(0, DEPTH*INSTR_SIZE + 1):
            #  MIPS has jump delay slots, this means that the instruction 
            # immediatly after the jump is executed with the jump
            instructions = self._disas_all_instrs(ret_addr - i, ret_addr + 4)
            if instructions is None:
                continue
            gadget_str = ""
            for instr in instructions:
                gadget_str += f"{instr} ; "
                

            # https://github.com/tacnetsol/ida/blob/master/plugins/mipsrop/mipsrop.py#LL373C58-L373C58
            move_str = "move    $t9, "
            add_str = "addiu   $t9, "
            control_reg = ""
            t9_control_move = gadget_str.find(move_str)
            if t9_control_move != -1:
                t9_control_move += len(move_str)
                control_reg = gadget_str[t9_control_move:gadget_str.find(" ;", t9_control_move)]

            t9_control_add = gadget_str.find(add_str)
            if t9_control_add != -1:
                t9_control_add += len(add_str)
                control_reg = gadget_str[t9_control_add:gadget_str.find(" ;", t9_control_add)]
                if control_reg.__contains__("$t9"):
                    control_reg = ""
            if control_reg != "":
                gadget_rva = ret_addr - i - self.bv.start
                gadgets[gadget_rva] = (f"{gadget_str}", control_reg)
        return gadgets


    def _find_gadgets_in_data(
        self, insts: tuple[list[str], int]
    ) -> dict[int, (str,str)]:
        """
        find ret instructions and spawn a thread to calculate gadgets
        """
        gadgets: dict[int, (str, str)] = dict()
        for _, bytecodes in _RET_INSTRS.items():
            for bytecode in bytecodes:
                next_start = insts[0][1]
                next_ret_addr = 0
                while next_start < insts[-1][1]:
                    next_ret_addr = self.bv.find_next_data(next_start, bytecode)
                    if next_ret_addr is None:
                        break

                    # TODO thread this?
                    gadgets = self._calculate_gadget_from_ret(gadgets, next_ret_addr)
                    next_start = next_ret_addr + len(bytecode)
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
        all_gadgets = ""
        found = []
        gadgets = dict(sorted(gadgets.items()))
        # print(gadgets)
        for addr, gadget in sorted(gadgets.items(), key=itemgetter(1)):
            if gadget not in found:
                gadget_str = " ".join(gadget[0].split())
                addr = addr + self.bv.start  # make sure addrs are correct
                
                f_gadget_str = (
                    f"[0x{addr:016x}](binaryninja://?expr={addr:08x})  \tControl reg: <span style='color: green;'>{gadget[1]}</span>\t{gadget_str}\n\n"
                )
                all_gadgets += f_gadget_str

                # stackfinder
                if re.search(r"addiu \$.*, \$sp", f_gadget_str):
                    stackfinder_gadgets += f_gadget_str
                # lia0
                if "li $a0" in f_gadget_str:
                    lia0_gadets += f_gadget_str
                # registers
                if re.search(r"lw \$.*, 0x[0-9a-z]{0,4}\(\$sp", f_gadget_str):
                    registers_gadgets += f_gadget_str
                # system
                if "addiu $a0, $sp" in f_gadget_str:
                    system_gadgets += f_gadget_str
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

        markdown += "[+] all gadgets\n\n"
        body += all_gadgets

        markdown += body
        self.bv.show_markdown_report(title, markdown)