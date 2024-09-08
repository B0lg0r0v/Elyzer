import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

class Colors:
    @staticmethod
    def red(str):
        return Fore.RED + str + Style.RESET_ALL
    
    @staticmethod
    def green(str):
        return Fore.GREEN + str + Style.RESET_ALL
    
    @staticmethod
    def yellow(str):
        return Fore.YELLOW + str + Style.RESET_ALL
    
    @staticmethod
    def blue(str):
        return Fore.BLUE + str + Style.RESET_ALL
    
    @staticmethod
    def magenta(str):
        return Fore.MAGENTA + str + Style.RESET_ALL
    
    @staticmethod
    def cyan(str):
        return Fore.CYAN + str + Style.RESET_ALL
    
    @staticmethod
    def white(str):
        return Fore.WHITE + str + Style.RESET_ALL
    
    @staticmethod
    def black(str):
        return Fore.BLACK + str + Style.RESET_ALL
    
    @staticmethod
    def light_red(str):
        return Fore.LIGHTRED_EX + str + Style.RESET_ALL
    
    @staticmethod
    def light_green(str):
        return Fore.LIGHTGREEN_EX + str + Style.RESET_ALL
    
    @staticmethod
    def light_yellow(str):
        return Fore.LIGHTYELLOW_EX + str + Style.RESET_ALL

    @staticmethod
    def light_blue(str):
        return Fore.LIGHTBLUE_EX + str + Style.RESET_ALL
    
    @staticmethod
    def light_magenta(str):
        return Fore.LIGHTMAGENTA_EX + str + Style.RESET_ALL
        
    
def banner():
    print(r"""
          
   ____ ____  __ ____   ____ ___ 
  / __// /\ \/ //_  /  / __// _ \
 / _/ / /__\  /  / /_ / _/ / , _/
/___//____//_/  /___//___//_/|_| v0.4.0
                                  
    """+
    (Colors.light_blue("\n\tAuthor: B0lg0r0v") + Colors.light_blue("\n\thttps://arthurminasyan.com\n")))

