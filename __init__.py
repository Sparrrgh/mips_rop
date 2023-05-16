from binaryninja import *
from .mips_rop import *

from binaryninja import user_plugin_path, core_version
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.log import (log_error, log_debug, log_alert, log_warn)
from binaryninja.settings import Settings
from binaryninja.interaction import get_directory_name_input
import binaryninjaui
from binaryninjaui import (getMonospaceFont, UIAction, UIActionHandler, Menu, UIContext)
from PySide6.QtWidgets import (QLineEdit, QPushButton, QApplication, QWidget,
     QVBoxLayout, QHBoxLayout, QDialog, QFileSystemModel, QTreeView, QLabel, QSplitter,
     QInputDialog, QMessageBox, QHeaderView, QKeySequenceEdit, QCheckBox, QMenu, QTextEdit)
from PySide6.QtCore import (QDir, Qt, QFileInfo, QItemSelectionModel, QSettings, QUrl)
from PySide6.QtGui import (QFontMetrics, QDesktopServices, QKeySequence, QIcon, QColor, QAction)


# https://github.com/Vector35/snippets/blob/a10096727be5bb8d17c88fab33ed43ff12a736e4/__init__.py#L190

class RopSettings(QDialog):
    def __init__(self, context, parent=None):
        super(RopSettings, self).__init__(parent)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.title = QLabel(self.tr("Settings for mips_rop"))
        self.saveButton = QPushButton(self.tr("&Save"))
        self.closeButton = QPushButton(self.tr("Close"))
        self.setWindowTitle(self.title.text())
        self.columns = 2
        self.context = context

        Settings().register_group("ropsettings", "ROP settings")

        Settings().register_setting("ropsettings.depth", """
            {
                "title" : "Depth of gadget search",
                "type" : "number",
                "default" : 4,
                "description" : "Maximum depth of the gadgets that will be searched",
                "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
            }
            """)

        depth = Settings().get_integer("ropsettings.depth")
        print(depth)
        self.depth = QLineEdit(f"{depth}")

        font = getMonospaceFont(self)
        font = QFontMetrics(font)

        # create layout and add widgets
        optionsAndButtons = QVBoxLayout()

        options = QHBoxLayout()
        options.addWidget(QLabel("Depth"))
        options.addWidget(self.depth)

        buttons = QHBoxLayout()
        buttons.addWidget(self.closeButton)
        buttons.addWidget(self.saveButton)

        optionsAndButtons.addLayout(options)
        optionsAndButtons.addLayout(buttons)

        vlayoutWidget = QWidget()
        vlayout = QVBoxLayout()
        vlayout.addLayout(optionsAndButtons)
        vlayoutWidget.setLayout(vlayout)

        # Set dialog layout
        self.setLayout(vlayout)

         # Add signals
        self.saveButton.clicked.connect(self.save)
        self.closeButton.clicked.connect(self.close)
        
        # self.resize(1000, 640)
        self.showNormal()   # fixes bug that maximized windows are stuck
        self.settings = QSettings("", "mips_rop")
        
    def save(self):
        Settings().set_integer("ropsettings.depth", int(self.depth.text()))
        self.close()

def openSettings(context):
    settings = RopSettings(context, parent=context.widget)
    settings.open()

def find_rop_gadgets(bv):
    rop_search = ROPSearch(bv)
    rop_search.start()

if __name__ == "__main__":
    print("from main")
else:
    PluginCommand.register(
        "mips_rop\\Find ROP Gadgets",
        "finds rop gadgets in current binary",
        find_rop_gadgets
    )
	
    UIAction.registerAction("mips_rop\\Settings")
    UIActionHandler.globalActions().bindAction("mips_rop\\Settings", UIAction(openSettings))
    Menu.mainMenu("Plugins").addAction("mips_rop\\Find ROP Gadgets", "mips_rop")
    Menu.mainMenu("Plugins").addAction("mips_rop\\Settings", "mips_rop")