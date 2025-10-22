# DirtyTypes.py
# This script allows you to create data structures via inserting C code into the popup dialog
# instead of using the painful GUI option... 

#@author J. DeFrancesco
#@category DataTypes
#@menupath Tools.Parse C Structs


from ghidra.app.util.cparser.C  import CParser
from ghidra.program.model.data import DataTypeConflictHandler
from ghidra.util import Msg
from java.awt import Dimension
from javax.swing import JTextArea, JScrollPane, JOptionPane

def run():
    # Multiline input box for struct text
    text_area = JTextArea(25, 80)
    text_area.setLineWrap(True)
    text_area.setWrapStyleWord(True)
    scroll = JScrollPane(text_area)
    scroll.setPreferredSize(Dimension(800, 500))

    result = JOptionPane.showConfirmDialog(
        None, scroll, "Enter your C typedefs / struct:", 
        JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE
    )

    if result != JOptionPane.OK_OPTION:
        Msg.info(None, "User cancelled input.")
        return

    c_code = text_area.getText().strip()
    if not c_code:
        Msg.showError(None, "Error", "No C code provided!")
        return

    dtm = currentProgram.getDataTypeManager()

    try:
        # Use Ghidras built-in C preprocessor & parser
        pp = CParser(dtm)
        parsed = pp.parse(c_code)

        dtm.addDataType(parsed, None)


        print("Success!")
    except Exception as e:
        print(e)
        
if __name__ == "__main__":
    run()
