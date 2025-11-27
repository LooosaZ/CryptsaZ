import os
version = "4.1.1"

def logoPrint():
    # Limpeza do ecrâ e impressão do logótipo
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""\033CryptsaZ: Application for Confidentiality and Integrity v.{version}\033[0m
    """)
    print("--------------------------------------")