#@category DataTypes
#@menupath Tools.User Parse C Structs

"""
This script allows the user to paste C-style typedefs / structs directly,
and Ghidra will parse them and add them to the current program's DataTypeManager.
"""

from ghidra.app.util.cparser.C import CParserUtils
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.util import Msg
from javax.swing import JOptionPane

def run():
    # Prompt the user for their C struct/typedef definitions
    user_input = JOptionPane.showInputDialog(
        None,
        "Enter your C typedefs/structs here:",
        "Parse C Structs",
        JOptionPane.PLAIN_MESSAGE
    )
    
    # If user cancels, exit
    if user_input is None:
        Msg.info(self, "User cancelled.")
        return

    # Trim whitespace
    c_text = user_input.strip()
    
    if c_text == "":
        Msg.showError(self, None, "Error", "No C code provided!")
        return

    dtm = currentProgram.getDataTypeManager()

    try:
        # Parse the C code into the DataTypeManager
        CParserUtils.parseString(c_text, dtm, DataTypeConflictHandler.DEFAULT_HANDLER)
        Msg.showInfo(self, "Success", "✅ C structs/typedefs parsed and imported successfully.")
    except Exception as e:
        Msg.showError(self, None, "Parsing Error", "❌ Failed to parse C code:\n\n" + str(e))