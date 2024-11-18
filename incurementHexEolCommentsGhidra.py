from ghidra_program.model.address import AddressSet
from ghidra.app.script import GhidraScript

class AddHexCommentsScript(GhidraScript):
    def run(self):
        print("Add hex comments")
        print(currentProgram)

        #check if currentProgram is valid
        if not currentProgram:
            print("Error: no program loaded Please open a program and run the script again")
            return
        
        hex_values = 0xC58  
        start_address = toAddr(0x000ef574)
        end_address = toAddr(0x000ef6c0)
        print("Script started. Processing from address {} to {}".format(start_address, end_address))

        add_comment = True #start with true to comment on first address
        current_address = start_address
        while current_address and current_address.compareTo(end_address) <= 0:
            if add_comment:
                comment = "0x{:08x}".format(hex_values)
                print("Adding comment {} to address {}".format(comment, current_address))
                setEOLComment(current_address, comment)
                hex_values += 1 #increment hex value

                if hex_values > 0xCFF
                    print("Hex value limit reached, stopping script")
                    break

            #toggle the flag to skip every other address
            add_comment = not add_comment

            #move to the next address
            current_address = current_address.add(1) #increment address

script = AddHexCommentsScript()
script.run()

