from ensurepip import bootstrap

GATE_CYCLE = 1
BTSTRP_CYCLE = 2

RS_SIZE = 3


class reservation_station_entry:
    def __init__(self, id, busy, rs1, rs2, val1, val2, dst):
        self._id = id
        self._busy = busy
        self._rs1 = rs1
        self._rs2 = rs2
        self._val1 = val1
        self._val2 = val2
        self._dst = dst

    # Getter and Setter for ID
    @property
    def ID(self):
        return self._id

    @ID.setter
    def ID(self, value):
        self._id = value

    # Getter and Setter for Busy
    @property
    def Busy(self):
        return self._busy

    @Busy.setter
    def Busy(self, value):
        self._busy = value

    # Getter and Setter for RS1
    @property
    def RS1(self):
        return self._rs1

    @RS1.setter
    def RS1(self, value):
        self._rs1 = value

    # Getter and Setter for RS2
    @property
    def RS2(self):
        return self._rs2

    @RS2.setter
    def RS2(self, value):
        self._rs2 = value

    # Getter and Setter for Val1
    @property
    def Val1(self):
        return self._val1

    @Val1.setter
    def Val1(self, value):
        self._val1 = value

    # Getter and Setter for Val2
    @property
    def Val2(self):
        return self._val2

    @Val2.setter
    def Val2(self, value):
        self._val2 = value

    # Getter and Setter for dst
    @property
    def dst(self):
        return self._dst

    @dst.setter
    def dst(self, value):
        self._dst = value


class Register_Entry:
    """
    Represents an entry in the Register Table with three fields.
    You can customize the field types and names as needed (e.g., name: str, value: int, busy: bool).
    """

    def __init__(self, wait_for, value, bootstrap):
        self._wait_for = wait_for
        self._value = value
        self._bootstrap = bootstrap

    # Getter and Setter for field2
    @property
    def wait_for(self):
        return self._wait_for

    @wait_for.setter
    def wait_for(self, rs_name):
        self._wait_for = rs_name

    # Getter and Setter for field3
    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value

    # Getter and Setter for field3
    @property
    def bootstrap(self):
        return self._bootstrap

    @bootstrap.setter
    def bootstrap(self, bootstrap):
        self._bootstrap = bootstrap

    def __repr__(self):
        return f"Entry(dst={self.dst}, waiting_for={self.wait_for}, value={self.value}, bootstrap={self._bootstrap})"


class RegisterTable:
    """
    Holds a list of Entry objects. Provides methods to manage the entries.
    """

    def __init__(self):
        self.entries = {}

    def add_entry(self, destination, entry):
        """
        Adds a new Entry to the table.
        """
        if isinstance(entry, Register_Entry):
            self.entries[destination] = entry
        else:
            raise ValueError("Only Entry objects can be added.")

    def get_entry(self, destination) -> Register_Entry:
        """
        Retrieves an Entry by destination.
        """
        if destination in self.entries:
            return self.entries[destination]
        else:
            return None

    def remove_entry(self, destination):
        """
        Removes an Entry by destination.
        """
        if destination in self.entries:
            self.entries.pop(destination)

    def exists(self, destination):
        if destination in self.entries:
            return True
        else:
            return False

    def update_entry(self, destination, entry):
        if destination in self.entries:
            self.entries[destination] = entry
        else:
            print("The provided destination does not exist in the register table.")

    def __len__(self):
        return len(self.entries)

    def __repr__(self):
        return f"RegisterTable(entries={self.entries})"


class Controller:
    def __init__(self, inst, register_table):
        self._inst = inst
        self.register_tbl = register_table
        self.AND_RS = [reservation_station_entry("AND1", 0, "-", "-", '-', '-', '0'),
                       reservation_station_entry("AND2", 0, "-", "-", '-', '-', '0'),
                       reservation_station_entry("AND2", 0, "-", "-", '-', '-', '0')]

        self.OR_RS = [reservation_station_entry("OR1", 0, "-", "-", '-', '-', '0'),
                      reservation_station_entry("OR2", 0, "-", "-", '-', '-', '0'),
                      reservation_station_entry("OR2", 0, "-", "-", '-', '-', '0')]

        self.XOR_RS = [reservation_station_entry("XOR1", 0, "-", "-", '-', '-', '0'),
                       reservation_station_entry("XOR2", 0, "-", "-", '-', '-', '0'),
                       reservation_station_entry("XOR2", 0, "-", "-", '-', '-', '0')]

        self.NAND_RS = [reservation_station_entry("NAND1", 0, "-", "-", '-', '-', '0'),
                        reservation_station_entry("NAND2", 0, "-", "-", '-', '-', '0'),
                        reservation_station_entry("NAND2", 0, "-", "-", '-', '-', '0')]

        self.NOR_RS = [reservation_station_entry("NOR1", 0, "-", "-", '-', '-', '0'),
                       reservation_station_entry("NOR2", 0, "-", "-", '-', '-', '0'),
                       reservation_station_entry("NOR2", 0, "-", "-", '-', '-', '0')]

        self.XNOR_RS = [reservation_station_entry("XNOR1", 0, "-", "-", '-', '-', '0'),
                        reservation_station_entry("XNOR2", 0, "-", "-", '-', '-', '0'),
                        reservation_station_entry("XNOR2", 0, "-", "-", '-', '-', '0')]

    def decode_instruction(self):
        """
        Decodes an instruction string of the form:
        - 'Destination_name = operand1 Operation operand2' where Operation is &, |, ^, ~&, ~|, ~^
        - 'Destination_name = value' for initialization (value can be int, float, or string)

        Args:
            instruction (str): The instruction string to decode.

        Returns:
            dict: A dictionary containing:
                  - For binary operations: 'destination', 'operand1', 'operation', 'operand2'
                  - For initialization: 'destination', 'value', 'type' (indicating value type)
                  Returns None if the instruction is invalid.

        Example:
            >>> decode_instruction("dst = RS1 & RS2")
            {'destination': 'dst', 'operand1': 'RS1', 'operation': '&', 'operand2': 'RS2'}
            >>> decode_instruction("a = 123")
            {'destination': 'a', 'value': '123', 'type': 'int'}
            >>> decode_instruction("x = 3.14")
            {'destination': 'x', 'value': '3.14', 'type': 'float'}
            >>> decode_instruction("name = hello")
            {'destination': 'name', 'value': 'hello', 'type': 'str'}
        """
        # Valid operations for binary instructions
        valid_operations = {'&', '|', '^', '~&', '~|', '~^'}

        # Remove extra whitespace and split by '='
        instruction = self._inst.strip()
        if '=' not in instruction:
            return None

        parts = instruction.split('=', 1)  # Split on first '=' only
        if len(parts) != 2:
            return None

        destination = parts[0].strip()
        expression = parts[1].strip()

        # Check if it's an initialization instruction (no operation)
        expression_no_spaces = expression.replace(' ', '')
        if not any(op in expression_no_spaces for op in valid_operations):
            # Handle initialization: Destination_name = value
            value = expression.strip()
            if not destination or not value:
                return None

            return {
                'destination': destination,
                'value': value,
            }

        # Handle binary operation instruction
        for op in sorted(valid_operations, key=len, reverse=True):
            if op in expression:
                operands = expression.split(op)
                if len(operands) != 2:
                    return None
                operand1 = operands[0].strip()
                operand2 = operands[1].strip()

                # Validate that operands and destination are non-empty
                if not destination or not operand1 or not operand2:
                    return None

                return {
                    'destination': destination,
                    'operand1': operand1,
                    'operation': op,
                    'operand2': operand2,
                }

    def initialize_into_rs(self, destination, value):
        re = Register_Entry("-", value, False)
        self.register_tbl.add_entry(destination, re)

    def assign_to_rs(self, destination, operand1, op, operand2):
        if op == "&":
            # Is AND0 available?
            if self.AND_RS[0].Busy == 0:
                # Mark the corresponding reservation state as busy
                self.AND_RS[0].Busy = 1
                # Fill out the destination that will hold the result
                self.AND_RS[0].dst = destination.strip()
                # Get the current entry in the register table
                curnt_entry = self.register_tbl.get_entry(operand1)
                # if it is not -1, then it exists
                if curnt_entry != "-1":
                    # If the wait_for cell is null, then we can use the stored value
                    # Otherwise, we get the reservation station ID.
                    # This is applied for operand1 and operand2
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.AND_RS[0].Val1 = operand1.strip()
                        self.AND_RS[0].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.AND_RS[0].RS1 = operand1.strip()
                        self.AND_RS[0].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.AND_RS[0].Val2 = operand2.strip()
                        self.AND_RS[0].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.AND_RS[0].RS2 = operand2.strip()
                        self.AND_RS[0].Val2 = "-"

            # Is AND1 available?
            elif self.AND_RS[1].Busy == 0:
                # Mark the corresponding reservation state as busy
                self.AND_RS[1].Busy = 1
                self.AND_RS[1].dst = destination.strip()
                curnt_entry = self.register_tbl.get_entry(operand1)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.AND_RS[1].Val1 = operand1.strip()
                        self.AND_RS[1].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.AND_RS[1].RS1 = operand1.strip()
                        self.AND_RS[1].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.AND_RS[1].Val2 = operand2.strip()
                        self.AND_RS[1].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.AND_RS[1].RS2 = operand2.strip()
                        self.AND_RS[1].Val2 = "-"

            # Is AND2 available?
            elif self.AND_RS[2].Busy == 0:
                # Mark the corresponding reservation state as busy
                self.AND_RS[2].Busy = 1
                self.AND_RS[2].dst = destination.strip()
                curnt_entry = self.register_tbl.get_entry(operand1)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.AND_RS[2].Val1 = operand1.strip()
                        self.AND_RS[2].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.AND_RS[2].RS1 = operand1.strip()
                        self.AND_RS[2].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.AND_RS[2].Val2 = operand2.strip()
                        self.AND_RS[2].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.AND_RS[2].RS2 = operand2.strip()
                        self.AND_RS[2].Val2 = "-"

            else:
                print("No available reservation state for AND")
        elif op == "|":
            # Is OR0 available?
            if self.OR_RS[0].Busy == 0:
                # Mark the corresponding reservation state as busy
                self.OR_RS[0].Busy = 1
                # Fill out the destination that will hold the result
                self.OR_RS[0].dst = destination.strip()
                # Get the current entry in the register table
                curnt_entry = self.register_tbl.get_entry(operand1)
                # if it is not -1, then it exists
                if curnt_entry != "-1":
                    # If the wait_for cell is null, then we can use the stored value
                    # Otherwise, we get the reservation station ID.
                    # This is applied for operand1 and operand2 
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.OR_RS[0].Val1 = operand1.strip()
                        self.OR_RS[0].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.OR_RS[0].RS1 = operand1.strip()
                        self.OR_RS[0].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.OR_RS[0].Val2 = operand2.strip()
                        self.OR_RS[0].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.OR_RS[0].RS2 = operand2.strip()
                        self.OR_RS[0].Val2 = "-"

            # Is OR1 available?
            elif self.OR_RS[1].Busy == 0:
                self.OR_RS[1].Busy = 1
                self.OR_RS[1].dst = destination.strip()
                curnt_entry = self.register_tbl.get_entry(operand1)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.OR_RS[1].Val1 = operand1.strip()
                        self.OR_RS[1].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.OR_RS[1].RS1 = operand1.strip()
                        self.OR_RS[1].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.OR_RS[1].Val2 = operand2.strip()
                        self.OR_RS[1].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.OR_RS[1].RS2 = operand2.strip()
                        self.OR_RS[1].Val2 = "-"

            # Is OR2 available?
            elif self.OR_RS[2].Busy == 0:
                self.OR_RS[2].Busy = 1
                self.OR_RS[2].dst = destination.strip()
                curnt_entry = self.register_tbl.get_entry(operand1)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.OR_RS[2].Val1 = operand1.strip()
                        self.OR_RS[2].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.OR_RS[2].RS1 = operand1.strip()
                        self.OR_RS[2].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.OR_RS[2].Val2 = operand2.strip()
                        self.OR_RS[2].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.OR_RS[2].RS2 = operand2.strip()
                        self.OR_RS[2].Val2 = "-"

            else:
                print("No available reservation state for OR")
        elif op == "^":
            if self.XOR_RS[0].Busy == 0:
                self.XOR_RS[0].Busy = 1
                self.XOR_RS[0].dst = destination.strip()
                curnt_entry = self.register_tbl.get_entry(operand1)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.XOR_RS[0].Val1 = operand1.strip()
                        self.XOR_RS[0].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.XOR_RS[0].RS1 = operand1.strip()
                        self.XOR_RS[0].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.XOR_RS[0].Val2 = operand2.strip()
                        self.XOR_RS[0].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.XOR_RS[0].RS2 = operand2.strip()
                        self.XOR_RS[0].Val2 = "-"
            elif self.XOR_RS[1].Busy == 0:
                self.XOR_RS[1].Busy = 1
                self.XOR_RS[1].dst = destination.strip()
                curnt_entry = self.register_tbl.get_entry(operand1)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.XOR_RS[1].Val1 = operand1.strip()
                        self.XOR_RS[1].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.XOR_RS[1].RS1 = operand1.strip()
                        self.XOR_RS[1].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.XOR_RS[1].Val2 = operand2.strip()
                        self.XOR_RS[1].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.XOR_RS[1].RS2 = operand2.strip()
                        self.XOR_RS[1].Val2 = "-"
            elif self.XOR_RS[2].Busy == 0:
                self.XOR_RS[2].Busy = 1
                self.XOR_RS[2].dst = destination.strip()
                curnt_entry = self.register_tbl.get_entry(operand1)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.XOR_RS[2].Val1 = operand1.strip()
                        self.XOR_RS[2].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.XOR_RS[2].RS1 = operand1.strip()
                        self.XOR_RS[2].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.XOR_RS[2].Val2 = operand2.strip()
                        self.XOR_RS[2].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.XOR_RS[2].RS2 = operand2.strip()
                        self.XOR_RS[2].Val2 = "-"

            else:
                print("No available reservation state for XOR")
        elif op == "~&":
            if self.NAND_RS[0].Busy == 0:
                self.NAND_RS[0].Busy = 1
                self.NAND_RS[0].dst = destination.strip()
                curnt_entry = self.register_tbl.get_entry(operand1)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.NAND_RS[0].Val1 = operand1.strip()
                        self.NAND_RS[0].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.NAND_RS[0].RS1 = operand1.strip()
                        self.NAND_RS[0].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.NAND_RS[0].Val2 = operand2.strip()
                        self.NAND_RS[0].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.NAND_RS[0].RS2 = operand2.strip()
                        self.NAND_RS[0].Val2 = "-"
            elif self.NAND_RS[1].Busy == 0:
                self.NAND_RS[1].Busy = 1
                self.NAND_RS[1].dst = destination.strip()
                curnt_entry = self.register_tbl.get_entry(operand1)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.NAND_RS[1].Val1 = operand1.strip()
                        self.NAND_RS[1].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.NAND_RS[1].RS1 = operand1.strip()
                        self.NAND_RS[1].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.NAND_RS[1].Val2 = operand2.strip()
                        self.NAND_RS[1].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.NAND_RS[1].RS2 = operand2.strip()
                        self.NAND_RS[1].Val2 = "-"
            elif self.NAND_RS[2].Busy == 0:
                self.NAND_RS[2].Busy = 1
                self.NAND_RS[2].dst = destination.strip()
                curnt_entry = self.register_tbl.get_entry(operand1)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.NAND_RS[2].Val1 = operand1.strip()
                        self.NAND_RS[2].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.NAND_RS[2].RS1 = operand1.strip()
                        self.NAND_RS[2].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.NAND_RS[2].Val2 = operand2.strip()
                        self.NAND_RS[2].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.NAND_RS[2].RS2 = operand2.strip()
                        self.NAND_RS[2].Val2 = "-"

            else:
                print("No available reservation state for NAND")
        elif op == "~|":
            if self.NOR_RS[0].Busy == 0:
                self.NOR_RS[0].Busy = 1
                self.NOR_RS[0].dst = destination.strip()
                curnt_entry = self.register_tbl.get_entry(operand1)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.NOR_RS[0].Val1 = operand1.strip()
                        self.NOR_RS[0].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.NOR_RS[0].RS1 = operand1.strip()
                        self.NOR_RS[0].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.NOR_RS[0].Val2 = operand2.strip()
                        self.NOR_RS[0].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.NOR_RS[0].RS2 = operand2.strip()
                        self.NOR_RS[0].Val2 = "-"
            elif self.NOR_RS[1].Busy == 0:
                self.NOR_RS[1].Busy = 1
                self.NOR_RS[1].dst = destination.strip()
                curnt_entry = self.register_tbl.get_entry(operand1)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.NOR_RS[1].Val1 = operand1.strip()
                        self.NOR_RS[1].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.NOR_RS[1].RS1 = operand1.strip()
                        self.NOR_RS[1].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.NOR_RS[1].Val2 = operand2.strip()
                        self.NOR_RS[1].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.NOR_RS[1].RS2 = operand2.strip()
                        self.NOR_RS[1].Val2 = "-"
            elif self.NOR_RS[2].Busy == 0:
                self.NOR_RS[2].Busy = 1
                self.NOR_RS[2].dst = destination.strip()
                curnt_entry = self.register_tbl.get_entry(operand1)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.NOR_RS[2].Val1 = operand1.strip()
                        self.NOR_RS[2].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.NOR_RS[2].RS1 = operand1.strip()
                        self.NOR_RS[2].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.NOR_RS[2].Val2 = operand2.strip()
                        self.NOR_RS[2].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.NOR_RS[2].RS2 = operand2.strip()
                        self.NOR_RS[2].Val2 = "-"

            else:
                print("No available reservation state for NOR")
        elif op == "~^":
            if self.XNOR_RS[0].Busy == 0:
                self.XNOR_RS[0].Busy = 1
                self.XNOR_RS[0].dst = destination.strip()
                curnt_entry = self.register_tbl.get_entry(operand1)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.XNOR_RS[0].Val1 = operand1.strip()
                        self.XNOR_RS[0].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.XNOR_RS[0].RS1 = operand1.strip()
                        self.XNOR_RS[0].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.XNOR_RS[0].Val2 = operand2.strip()
                        self.XNOR_RS[0].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.XNOR_RS[0].RS2 = operand2.strip()
                        self.XNOR_RS[0].Val2 = "-"
            elif self.XNOR_RS[1].Busy == 0:
                self.XNOR_RS[1].Busy = 1
                self.XNOR_RS[1].dst = destination.strip()
                curnt_entry = self.register_tbl.get_entry(operand1)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.XNOR_RS[1].Val1 = operand1.strip()
                        self.XNOR_RS[1].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.XNOR_RS[1].RS1 = operand1.strip()
                        self.XNOR_RS[1].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.XNOR_RS[1].Val2 = operand2.strip()
                        self.XNOR_RS[1].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.XNOR_RS[1].RS2 = operand2.strip()
                        self.XNOR_RS[1].Val2 = "-"
            elif self.XNOR_RS[2].Busy == 0:
                self.XNOR_RS[2].Busy = 1
                self.XNOR_RS[2].dst = destination.strip()
                curnt_entry = self.register_tbl.get_entry(operand1)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand1 = curnt_entry.value
                        self.XNOR_RS[2].Val1 = operand1.strip()
                        self.XNOR_RS[2].RS1 = "-"
                    else:
                        operand1 = curnt_entry.wait_for
                        self.XNOR_RS[2].RS1 = operand1.strip()
                        self.XNOR_RS[2].Val1 = "-"

                curnt_entry = self.register_tbl.get_entry(operand2)
                if curnt_entry != "-1":
                    if curnt_entry.wait_for == "-":
                        operand2 = curnt_entry.value
                        self.XNOR_RS[2].Val2 = operand2.strip()
                        self.XNOR_RS[2].RS2 = "-"
                    else:
                        operand2 = curnt_entry.wait_for
                        self.XNOR_RS[2].RS2 = operand2.strip()
                        self.XNOR_RS[2].Val2 = "-"

            else:
                print("No available reservation state for AND")
        else:
            print("Undefined operation: ", op)

    def update_register_table(self, destination, wait_for, value, _bootstrap=0):
        new_entry = Register_Entry(wait_for, value, _bootstrap)
        self.register_tbl.update_entry(destination, new_entry)
        print(f"Updated register table for {destination}")

    def bootstrap(self, destination):
        # entry.bootstrap()
        entry = self.register_tbl.get_entry(destination)
        self.update_register_table(destination, entry.wait_for, entry.value, _bootstrap=1)
        print(f"Entry {destination} is bootstrapped")
