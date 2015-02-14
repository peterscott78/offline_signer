
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from ui import *

class sign_single_tx(QWidget):

	def __init__(self):
		super(sign_single_tx, self).__init__()

	def showUI(self, parent):

		# Initialize widget
		widget = PanelWidget(parent, 'Sign Single Transaction', 'You may sign an individual transaction by entering the raw hex code of the transaction below.  This is the same hex code as the createrawtransaction() function from bitcoind will provide.')

		# Text box
		self.txtRawHexCode = QPlainTextEdit()
		self.txtRawHexCode.setMaximumHeight(80)

		# Push button
		buttonSignSingleTx = QPushButton(self.tr('Sign Single Transaction'), self)
		buttonSignSingleTx.setMaximumWidth(250)
		#buttonSignSingleTx.clicked.connect(self.sign_single_tx)

		# Add to layout
		widget.layout.addWidget(QLabel(self.tr('Hex Code:  ')), 2, 0, Qt.AlignTop)
		widget.layout.addWidget(self.txtRawHexCode, 2, 1, Qt.AlignTop)
		widget.layout.addWidget(buttonSignSingleTx, 3, 1, 1, 1, Qt.AlignRight)

		# Return
		return widget



