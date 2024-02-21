# --------------------------------
# Coffeur.py
# Author: Francesco Buldo
# Date: 2023-10-24
# --------------------------------
""" 
Coffeur is a python module that allows to read debug information from TI C2000 COFF files.
It is based on the pyelftools library and the TI COFF file format specification.
It also allows to read variable values and derefere points from a memory dump if the read function is provided ( Env.read_memory(address, size) )
"""

import io
from . import ti_coff
from .elftools.dwarf.dwarfinfo import DWARFInfo, DwarfConfig
from .elftools.dwarf.die import DIE
from .elftools.common.utils import bytes2str
import regex as re
from enum import Enum
import struct


class env:
    default_pointer_size = 2
    default_bits_per_byte = 16

    def read_memory(address, size):
        return bytes([0] * 2 * size)

    endianness = "<"
    type_to_struct_format = {
        "char": "b",
        "unsigned char": "B",
        "short": "h",
        "unsigned short": "H",
        "int": "i",
        "unsigned int": "I",
        "long": "l",
        "unsigned long": "L",
        "long long": "q",
        "unsigned long long": "Q",
        "float": "f",
        "double": "d",
    }


def get_die_name(die):
    if "DW_AT_name" not in die.attributes:
        return "<anonymous>"
    return bytes2str(die.attributes["DW_AT_name"].value)


def calculate_location(die: DIE) -> int:
    """calculates the location of a variable"""
    location_attribute = die.attributes["DW_AT_location"]
    if location_attribute is None:
        raise Exception("calculate_location: no DW_AT_location attribute found")

    if location_attribute.form == "DW_FORM_exprloc":
        return location_attribute.value[0]
    elif location_attribute.form == "DW_FORM_block1":
        opcode = location_attribute.value[0]
        val = location_attribute.value[1:]
        if opcode == 0x3:
            loc = 0
            # littel endian
            for i in range(0, len(val)):
                loc = loc + (val[i] << (8 * i))
            return loc
        else:
            raise Exception("calculate_location: opcode not supported")


def calculate_member_offset(die: DIE) -> int:
    """calculates the location of a member"""
    location_attribute = die.attributes["DW_AT_data_member_location"]
    if location_attribute is None:
        raise Exception(
            "calculate_location: no DW_AT_data_member_location attribute found"
        )

    if location_attribute.form == "DW_FORM_data1":
        return location_attribute.value[0]
    elif location_attribute.form == "DW_FORM_block1":
        opcode = location_attribute.value[0]
        if opcode == 0x3 or opcode == 0x23:
            return location_attribute.value[1]
        else:
            raise Exception(f"calculate_location: opcode {opcode} not supported")
    else:
        raise Exception(
            f"calculate_location: form {location_attribute.form} not supported"
        )


class BitFieldMemberInfo:
    def __init__(self, bit_offset: int, bit_size: int):
        self.bit_offset = bit_offset
        self.bit_size = bit_size


class TypeInfo:
    def __init__(self, name: str, size: int):
        self.name: str = name
        self.size: int = size

    def is_struct(self) -> bool:
        return False

    def is_enum(self) -> bool:
        return False

    def is_typedef(self) -> bool:
        return False

    def is_array(self) -> bool:
        return False

    def is_pointer(self) -> bool:
        return False

    def is_base_type(self) -> bool:
        return False

    def is_union(self) -> bool:
        return False

    def get_type(self) -> str:
        return self.name

    def get_size(self) -> int:
        return self.size

    def final_type(self) -> "TypeInfo":
        return self

    @staticmethod
    def parse(die: DIE) -> "TypeInfo":
        if die.tag == "DW_TAG_typedef":
            return Typedef(die)
        elif die.tag == "DW_TAG_enumeration_type":
            return EnumType(die)
        elif die.tag == "DW_TAG_base_type":
            return BaseType(die)
        elif die.tag == "DW_TAG_pointer_type":
            return PointerType(die)
        elif die.tag == "DW_TAG_array_type":
            return ArrayType(die)
        elif die.tag == "DW_TAG_const_type":
            return ConstType(die)
        elif die.tag == "DW_TAG_structure_type":
            return StructDefinition(die)
        elif die.tag == "DW_TAG_union_type":
            return UnionDefinition(die)
        elif die.tag == 'DW_TAG_unspecified_type':
            return UnspecifiedType(die)
        elif die.tag == "DW_TAG_volatile_type" or die.tag == "DW_TAG_lo_user":
            # skipped tags
            return TypeInfo.parse(
                die.dwarfinfo.get_DIE_from_refaddr(die.attributes["DW_AT_type"].value)
            )
        else:
            raise Exception(f"TypeInfo.parse: tag {die.tag} not supported")


class MemberInfo:
    def __init__(
        self,
        name: str,
        offset: int,
        type: TypeInfo,
        bitfield_info: BitFieldMemberInfo = None,
    ):
        self.name = name
        self.offset = offset
        self.type = type
        self.bitfield_info = bitfield_info


class EnumType(TypeInfo):
    def __init__(self, die: DIE):
        name: str = get_die_name(die)
        size = die.attributes["DW_AT_byte_size"].value
        super().__init__(name, size)

    def is_enum(self) -> bool:
        return True


class ArrayType(TypeInfo):
    def __init__(self, die: DIE):
        self.target_type = TypeInfo.parse(
            die.dwarfinfo.get_DIE_from_refaddr(die.attributes["DW_AT_type"].value)
        )
        self.size = die.attributes["DW_AT_byte_size"].value
        self.element_count = (
            self.size / self.target_type.size
        )  # die.attributes["DW_AT_upper_bound"].value
        name = self.target_type.name + "[" + str(self.element_count) + "]"
        super().__init__(name, self.size)

    def is_array(self) -> bool:
        return True

    def get_element_count(self) -> int:
        return self.element_count


class Typedef(TypeInfo):
    def __init__(self, die: DIE):
        name: str = get_die_name(die)
        self.target_type = TypeInfo.parse(
            die.dwarfinfo.get_DIE_from_refaddr(die.attributes["DW_AT_type"].value)
        )
        super().__init__(name, self.target_type.get_size())

    def get_member(self, name: str) -> tuple[int, TypeInfo]:
        self.target_type.get_member(name)

    def get_members(self) -> list[MemberInfo]:
        return self.target_type.get_members()

    def get_size(self) -> int:
        return self.target_type.get_size()

    def is_typedef(self) -> bool:
        return True

    def final_type(self) -> TypeInfo:
        ft = self.target_type
        while type(ft) is Typedef:
            ft = ft.target_type
        return ft

class BaseType(TypeInfo):
    def __init__(self, die: DIE):
        name: str = get_die_name(die)
        size = die.attributes["DW_AT_byte_size"].value
        super().__init__(name, size)

    def is_base_type(self) -> bool:
        return True

class UnspecifiedType(TypeInfo):
    def __init__(self, die: DIE):
        name: str = get_die_name(die)
        size = 0 # die.attributes["DW_AT_byte_size"].value
        super().__init__(name, size)

    def is_base_type(self) -> bool:
        return True

class PointerType(TypeInfo):
    def __init__(self, die: DIE):
        size: int = (
            env.default_pointer_size
        )  # die.attributes["DW_AT_address_class"].value / 8
        self.target_type = TypeInfo.parse(
            die.dwarfinfo.get_DIE_from_refaddr(die.attributes["DW_AT_type"].value)
        )
        name: str = self.target_type.name + "*"
        super().__init__(name, size)

    def is_pointer(self) -> bool:
        return True


class ConstType(TypeInfo):
    def __init__(self, die: DIE):
        self.target_type = TypeInfo.parse(
            die.dwarfinfo.get_DIE_from_refaddr(die.attributes["DW_AT_type"].value)
        )
        name: str = "const " + self.target_type.name
        super().__init__(name, self.target_type.get_size())


class StructDefinition(TypeInfo):
    def __init__(self, die: DIE):
        name: str = "struct " + get_die_name(die)
        size: int = die.attributes["DW_AT_byte_size"].value
        super().__init__(name, size)

        self.members: dict[str, MemberInfo] = {}
        for child in [x for x in die.iter_children() if x.tag == "DW_TAG_member"]:
            member_name = get_die_name(child)
            member_type = TypeInfo.parse(
                die.dwarfinfo.get_DIE_from_refaddr(child.attributes["DW_AT_type"].value)
            )
            member_offset = calculate_member_offset(child)
            bitInfo = None
            if "DW_AT_bit_offset" in child.attributes:
                bit_offset = child.attributes["DW_AT_bit_offset"].value
                bit_size = child.attributes["DW_AT_bit_size"].value
                bitInfo = BitFieldMemberInfo(bit_offset, bit_size)

            self.members[member_name] = MemberInfo(
                member_name, member_offset, member_type, bitInfo
            )

    def get_member(self, name: str) -> tuple[int, TypeInfo]:
        """returns the offset and the type of the member"""
        if name not in self.members:
            raise Exception(f"get_member: member '{name}' not found inf {self.name}")
        return self.members[name]

    def get_members(self) -> list[MemberInfo]:
        return self.members.values()

    def is_struct(self) -> bool:
        return True


class UnionDefinition(StructDefinition):
    def __init__(self, die: DIE):
        super().__init__(die)
        self.name = "union " + get_die_name(die)

    def is_struct(self) -> bool:
        return False

    def is_union(self) -> bool:
        return True


class Variable:
    def __init__(
        self,
        path: str,
        die: DIE = None,
        address: int = None,
        type: TypeInfo = None,
        bit_field_info: BitFieldMemberInfo = None,
    ):
        self.die = die
        self.address: int = address
        self.path = path
        self.bit_size = None
        self.bit_offset = None
        self.bit_size = None

        if self.die is not None:
            if not (address is None and type is None and bit_field_info is None):
                raise Exception(
                    "Variable: provide only die or (address and type), not both"
                )

            self.dwarfInfo: DWARFInfo = die.dwarfinfo
            self.name: str = get_die_name(self.die)
            type_die = self.die.attributes["DW_AT_type"].value
            type_die = self.dwarfInfo.get_DIE_from_refaddr(type_die)
            self.address = calculate_location(die)
            self.type: TypeInfo = TypeInfo.parse(type_die)
        else:
            if address is None or type is None:
                raise Exception("Variable: provide die or (address and type)")
            self.type = type
            self.address = address
            self.bit_field_info = bit_field_info

    @staticmethod
    def from_die(die: DIE) -> "Variable":
        return Variable(path=get_die_name(die), die=die)

    @staticmethod
    def from_address(
        path: str,
        address: int,
        type: TypeInfo,
        bit_field_info: BitFieldMemberInfo = None,
    ) -> "Variable":
        return Variable(
            path=path, address=address, type=type, bit_field_info=bit_field_info
        )

    def get_member(self, name: str) -> "Variable":
        while type(self.type) is Typedef:
            self.type = self.type.target_type

        if not isinstance(self.type, StructDefinition):
            raise Exception(f"get_member: the variable {self.path} is not a struct ")
        memberInfo: MemberInfo = self.type.get_member(name)
        return Variable.from_address(
            self.get_member_path(memberInfo),
            address=self.address + memberInfo.offset,
            type=memberInfo.type,
            bit_field_info=memberInfo.bitfield_info,
        )

    def dereference(self) -> "Variable":
        if type(self.type) is not PointerType:
            raise Exception(f"get_member: the variable {self.path} is not a pointer ")
        value = self.get_value()
        return Variable.from_address(
            path=f"*({self.path})", address=value, type=self.type.target_type
        )

    def get_element(self, index: int) -> TypeInfo:
        if type(self.type) is ArrayType:
            address = self.address + index * self.type.target_type.get_size()
        elif type(self.type) is PointerType:
            firstElem = self.dereference()
            address = firstElem.address + index * self.type.target_type.get_size()
        else:
            raise Exception(
                f"get_element: the variable {self.path} is not an array or pointer "
            )
        return Variable.from_address(
            path=f"{self.path}[{index}]", address=address, type=self.type.target_type
        )

    def get_value(self) -> int:
        targetType = self.type
        while type(targetType) is Typedef:
            targetType = targetType.target_type

        if targetType.is_pointer():
            raw_value = env.read_memory(self.address, targetType.get_size())
            size_to_format = {1: "B", 2: "H", 4: "I", 8: "Q"}
            return struct.unpack(
                env.endianness + size_to_format[len(raw_value)], raw_value
            )[0]
        elif targetType.is_base_type():
            raw_value = env.read_memory(self.address, self.type.get_size())
            format_str = env.type_to_struct_format[targetType.name]
            return struct.unpack(env.endianness + format_str, raw_value)[0]
        else:
            raise Exception(f"Variable.get_value: type {targetType} not supported ")

    def get_member_path(self, memberInfo: MemberInfo) -> str:
        if memberInfo.bitfield_info is not None:
            return f"{self.path}.{memberInfo.name}[{memberInfo.bitfield_info.bit_offset}:{memberInfo.bitfield_info.bit_size}]"
        return f"{self.path}.{memberInfo.name}"

    def get_members(self) -> list["Variable"]:
        if not isinstance(self.type.final_type(), StructDefinition):
            raise Exception(f"get_members: the variable {self.path} is not a struct ")
        members = []
        for memberInfo in self.type.get_members():
            members.append(
                Variable.from_address(
                    self.get_member_path(memberInfo),
                    address=self.address + memberInfo.offset,
                    type=memberInfo.type,
                    bit_field_info=memberInfo.bitfield_info,
                )
            )
        return members

    def get_size(self) -> int:
        return self.type.get_size()

    def __str__(self):
        return f"address: 0x{self.address:X} - type: {self.type.name} - size: {self.type.get_size()}"


class VariablePathIteratorCommand(Enum):
    GET_GLOBAL = "get_global"
    GET_MEMBER = "get_member"
    GET_ARRAY_ELEMENT = "get_array_element"
    DEREFERENCE = "dereference"


class VariablePathIterator:
    """Allows to itereate over a variable path
    Example: my_var.a[1].d->e
    expands to
    get global my_var
    get member a
    get array element 1
    get member d
    dereference
    get member e
    """

    def __init__(self, path: str, globalScope):
        self.path: str = path
        self.globla_scope = globalScope
        self.last = None
        self.length: int = len(path)
        self.current = 0
        self.parseSection = re.compile(
            r"(?<global>[a-zA-Z_][a-zA-Z_0-9]*)|"
            + r"[.](?<member>[a-zA-Z_][a-zA-Z_0-9]*)|"  # variable name
            + r"(\[(?<index>[0-9]+)\])|"  # variable name
            + r"(?<deref>->)"  # array index  # de name
        )

    def __iter__(self):
        return self

    def __next__(self) -> tuple[str, VariablePathIteratorCommand, str]:
        if self.current >= self.length:
            raise StopIteration

        re_match = self.parseSection.match(self.path, self.current)
        if re_match is None:
            raise Exception("internal error")
        self.current = re_match.end()

        if re_match.group("global"):
            if self.last and self.last[0] == VariablePathIteratorCommand.DEREFERENCE:
                self.last = VariablePathIteratorCommand.GET_MEMBER, re_match.group(
                    "global"
                )
            else:
                self.last = VariablePathIteratorCommand.GET_GLOBAL, re_match.group(
                    "global"
                )
        elif re_match.group("member"):
            self.last = VariablePathIteratorCommand.GET_MEMBER, re_match.group("member")
        elif re_match.group("index"):
            self.last = VariablePathIteratorCommand.GET_ARRAY_ELEMENT, re_match.group(
                "index"
            )
        elif re_match.group("deref"):
            self.last = VariablePathIteratorCommand.DEREFERENCE, None
        return self.last


class Dwarfer:
    def __init__(self, dwarfInfo: DWARFInfo):
        self.dwarfInfo: DWARFInfo = dwarfInfo

    def get_variable(self, symbol_name: str) -> Variable:
        """
        get the symbol information for a symbol name
        Example: get_variable("my_var.a.d")
                 returns a Variable object
        """
        current_variable = None
        var_path = ""
        for cmd, arg in VariablePathIterator(symbol_name, None):
            if cmd == VariablePathIteratorCommand.GET_GLOBAL:
                current_variable = self.get_global_variable(arg)
                var_path = arg
            elif cmd == VariablePathIteratorCommand.GET_MEMBER:
                current_variable = current_variable.get_member(arg)
                var_path = var_path + "." + arg
            elif cmd == VariablePathIteratorCommand.GET_ARRAY_ELEMENT:
                current_variable = current_variable.get_element(int(arg))
                var_path = var_path + "[" + arg + "]"
            elif cmd == VariablePathIteratorCommand.DEREFERENCE:
                current_variable = current_variable.dereference()
                var_path = f"*({var_path})"

        return current_variable

    def get_global_variable(self, name: str):
        symbolEntry = self.dwarfInfo.get_pubnames()[name]
        instanceDie = self.dwarfInfo.get_DIE_from_lut_entry(symbolEntry)
        return Variable.from_die(instanceDie)


class Expando(object):
    pass


class Coffeur:
    def __init__(self, coffFile: str, memoryDumpFile: str) -> None:
        c = ti_coff.Coff(coffFile)
        # gather data from the debug sections
        sections_data = {}
        # fill dictionary with data from all sections
        for section in c.sections:
            sections_data[section.name] = section.data

        dwconf = DwarfConfig(True, "c28x", 4)

        def getSection(name):
            if not name in sections_data:
                return None

            data = sections_data[name]
            obj = Expando()
            obj.stream = io.BytesIO(data)
            obj.name = name
            obj.size = len(data)
            return obj

        # function that gets an object that can be consumed by pyelftools
        # create a dwarfinfo object by providing the known sections
        dwarfinfo = DWARFInfo(
            dwconf,
            getSection(".debug_info"),
            getSection(".debug_aranges"),
            getSection(".debug_abbrev"),
            getSection(".debug_frame"),
            getSection(".eh_frame"),
            getSection(".debug_str"),
            getSection(".debug_loc"),
            getSection(".debug_ranges"),
            getSection(".debug_line"),
            getSection(".debug_pubtypes"),
            getSection(".debug_pubnames"),
            getSection(".debug_addr"),
            getSection(".debug_str_offsets"),
            getSection(".debug_line_str"),
            getSection(".debug_loclists"),
            getSection(".debug_rnglists"),
            getSection(".debug_sup"),
            getSection(".gnu_debugaltlink"),
        )

        self.dwarfer = Dwarfer(dwarfinfo)

    def print_var_info_and_value(self, path: str):
        var = self.dwarfer.get_variable(path)
        print(f"Info on {path} decoded to {var.path} ")
        print("   " + str(var))
        print("   value: ", var.get_value())

    def print_var_info(self, path: str):
        var = self.dwarfer.get_variable(path)
        print(f"Info on {path} decoded to {var.path} ")
        print("   " + str(var))

    def get_variable(self, path: str) -> "Variable":
        return self.dwarfer.get_variable(path)

    def get_variables(self) -> list["Variable"]:
        pub_names = self.dwarfer.dwarfInfo.get_pubnames()

        for name in pub_names:
            try:
                symbolEntry = pub_names[name]
                instanceDie = self.dwarfer.dwarfInfo.get_DIE_from_lut_entry(symbolEntry)
                if instanceDie.tag == "DW_TAG_variable":
                    yield Variable.from_die(instanceDie)
            except Exception as ex:
                print(f"Skipping variable {name} because {ex}")  # noqa: T001
