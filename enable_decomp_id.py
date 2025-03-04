# Enables "Decompiler Parameter ID" analysis and configures its settings.
#
# @category xref.Demo
#

from ghidra.app.script import GhidraScript

class EnableDecompilerParameterID(GhidraScript):
    def run(self):
        if currentProgram is None:
            print("No program is open! Aborting.")
            return

        print("Enabling 'Decompiler Parameter ID' analysis...")

        # Define the settings for "Decompiler Parameter ID"
        options_to_set = {
            "Decompiler Parameter ID": "true",  # Enable the analysis
            "Decompiler Parameter ID.Prototype Evaluation": "__thiscall",  # Example setting
            "Decompiler Parameter ID.Analysis Decompiler Timeout (sec)": "90",  # Set timeout
        }

        # Apply the settings
        setAnalysisOptions(currentProgram, options_to_set)

        print("Successfully enabled and configured 'Decompiler Parameter ID'!")

# Allow execution when running as a script (Optional, useful for debugging)
if __name__ == "__main__":
    script = EnableDecompilerParameterID()
    script.run()