"""Helper functions for writing to terminals and files."""
import os, shutil
import colorama
from colorama import Fore, Back, Style

from typing import List

def get_terminal_width() -> int:
    width, _ = shutil.get_terminal_size(fallback=(80, 24))

    # The Windows get_terminal_size may be bogus, let's sanify a bit.
    if width < 40:
        width = 80

    return width

def should_do_markup() -> bool:
  if os.environ.get("PY_COLORS") == "1":
      return True
  if os.environ.get("PY_COLORS") == "0":
      return False
  if "NO_COLOR" in os.environ:
      return False
  if "FORCE_COLOR" in os.environ:
      return True
  return True

class TerminalWriter:
  """
  Terminal colorized and fullwidth helper
  """
  
  markups = {
    "{red}": Fore.RED,
    "{green}": Fore.GREEN,
    "{blue}": Fore.BLUE,
    "{magenta}": Fore.MAGENTA,
    "{yellow}": Fore.YELLOW,
    
    "{dim}": Style.DIM,
    "{normal}": Style.NORMAL,
    "{bright}": Style.BRIGHT,
    "{bold}": "\033[1m",
    
    "{reset}": Style.RESET_ALL,
  }

  def __init__(self) -> None:
    self.hasmarkup = should_do_markup()
    colorama.init(autoreset=True)

  @property
  def fullwidth(self) -> int:
    if self._terminal_width is not None:
      return self._terminal_width
    return get_terminal_width()

  @fullwidth.setter
  def fullwidth(self, value: int) -> None:
    self._terminal_width = value

  def markup(self, text: str) -> str:
    """Colorized text through marks"""
    for markup in self.markups.keys():
      text = text.replace(markup, self.markups[markup])
    return text

  def get_stretched_line(self, line: str, char_pos:int = -1) -> str:
    """
    Get fullwidth line by expand the string through * index and char_pos indicator

    :param line: Line to fullwidth.
    :type line: str
    :param char_pos: Character position indicator, defaults to -1
    :type char_pos: int, optional
    :return: Stretched line.
    :rtype: str
    """
    stretched_line = line
    
    # Build line_no_markup
    _line_no_markup = line
    for markup in self.markups:
      _line_no_markup = _line_no_markup.replace(markup, '')  # Remove marks

    # TODO take into account escaped \*
    # Stretched line get factor N
    stretched_pos = [pos for pos, char in enumerate(
      _line_no_markup) if char == "*"]
    
    if len(stretched_pos):
      N = int((get_terminal_width() - (len(_line_no_markup) -
        len(stretched_pos))) / len(stretched_pos))

      # Factoring by streched line before positions
      for idx, pos in enumerate(stretched_pos):
        replaced_char = _line_no_markup[pos + char_pos]*N
        stretched_line = stretched_line.replace("*", replaced_char, idx+1)
    
    return stretched_line

  def write_lines(self, lines: list, printable:bool = True) -> List[str]:
    """
    Print given list of lines fullwidthed and colorized through markups

    :param lines: List of line to colorize
    :type lines: list
    :param printable: Should be printed, defaults to True
    :type printable: bool, optional
    :return: stdout lines to print
    :rtype: List[str]
    """
    markup_lines = []
    for line in lines:
      markup_lines.append(self.write_line(line, printable))
    return markup_lines

  def write_line(self, line: str, printable:bool = True) -> str:
    """
    Print given line fullwidthed and colorized through markups

    :param line: Line to colorize
    :type line: str
    :param printable: Should be printed, defaults to True
    :type printable: bool, optional
    :return: stdout line to print
    :rtype: str
    """
    # Stretch line though asterisk position
    line = self.get_stretched_line(line)
    
    # Line markup
    stdout_line = self.markup(line)
    if printable: print(stdout_line)
    
    return stdout_line
