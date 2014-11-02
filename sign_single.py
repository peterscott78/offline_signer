
import sys
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from binascii import hexlify
from bip32 import *
from rawtx import *

class sign_single(QDialog):

	def __init__(self, parent = None, hexcode = ''):
		QDialog.__init__(self, parent)
		#self.hexcode = '01000000024afdf8496fbb5f36bab35409c282a0bc8465190795e6966e8d50829a23f154950100000000ffffffff4afdf8496fbb5f36bab35409c282a0bc8465190795e6966e8d50829a23f154950100000000ffffffff021cc14704000000001976a914644863cd365a3e28afb1dcac390d4fa721959f7388ac53db5c0c000000001976a914a65c8a5b08e4807683543d88c30cc8933712a07388ac00000000'
		self.hexcode = str(hexcode)
		self.ui = sign_single
		self.ui.initUI(self)

	def initUI(self):

		# Decode transaction
		self.tx = rawtx()
		self.tx.decode_transaction(self.hexcode)

		# Set layout
		layout = QGridLayout()
		layout.setAlignment(Qt.AlignTop)
		layout.minimumSize()

		# Header
		lblHeader = QLabel('Sign Single Transaction')
		lblHeader.setStyleSheet("font-size: 14pt; font-weight: bold;")

		# Description
		lblDescription = QLabel('You may sign this individual transaction by entering the appropriate key indexes and BIP32 private key below.  If you do not have either, please contact your developer / technical team.')
		lblDescription.setStyleSheet("margin-bottom: 10px;")
		lblDescription.setWordWrap(True)

		# Table header layouts
		lblTableHeaderTxid = QLabel('TxID')
		lblTableHeaderVout = QLabel('Vout')
		lblTableHeaderKeyindex = QLabel('Keyindex')
		lblTableHeaderTxid.setStyleSheet("margin-bottom: 10px; font-weight: bold; text-align: center; background: #eee;")
		lblTableHeaderVout.setStyleSheet("margin-bottom: 10px; font-weight: bold; text-align: center; background: #eee;")
		lblTableHeaderKeyindex.setStyleSheet("margin-bottom: 10px; font-weight: bold; text-align: center; background: #eee;")

		# Add layout widgets
		layout.addWidget(lblHeader, 0, 0, 1, 4)
		layout.addWidget(lblDescription, 1, 0, 1, 4)
		layout.addWidget(lblTableHeaderTxid, 2, 0, 1, 2)
		layout.addWidget(lblTableHeaderVout, 2, 2, 1, 1)
		layout.addWidget(lblTableHeaderKeyindex, 2, 3, 1, 1)

		# Blank variables
		self.inputTexts = []

		# Go through inputs
		rownum = 3;
		for item in self.tx.inputs:

			txtKeyIndex = QLineEdit()
			txtKeyIndex.setMaximumWidth(80)

			layout.addWidget(QLabel(hexlify(item['txid'])), rownum, 0, 1, 2)
			layout.addWidget(QLabel(str(item['vout'])), rownum, 2)
			layout.addWidget(txtKeyIndex, rownum, 3)
			self.inputTexts.append({'keyindex': txtKeyIndex})
			rownum += 1

		# BIP32 Private Key
		self.txtPrivateKey = QPlainTextEdit()
		self.txtPrivateKey.setMaximumHeight(70)
		layout.addWidget(QLabel("BIP32 Private Key:"), rownum, 0, 1, 1, Qt.AlignTop)
		layout.addWidget(self.txtPrivateKey, rownum, 1, 1, 3)
		rownum += 1

		# Button box
		buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel);
		buttonBox.accepted.connect(self.ok)
		buttonBox.rejected.connect(self.cancel)
		layout.addWidget(buttonBox, rownum, 3, 1, 1, Qt.AlignRight)
		rownum += 1

		# Signed transaction
		self.txtSignedTransaction = QPlainTextEdit()
		self.txtSignedTransaction.setMaximumHeight(70)
		self.txtSignedTransaction.setReadOnly(True)
		self.txtSignedTransaction.setStyleSheet("background: #ccc;")
		layout.addWidget(QLabel("Signed Transaction:"), rownum, 0, 1, 1, Qt.AlignTop)
		layout.addWidget(self.txtSignedTransaction, rownum, 1, 1, 3)
		rownum += 1

		# Display dialog
		self.setLayout(layout)
		self.setWindowTitle("Sign Single Transaction")
		self.show()

	def ok(self):

		# Set key indexes
		num = 0
		for item in self.inputTexts:
			self.tx.set_keyindex(num, item['keyindex'].text(), self.txtPrivateKey.toPlainText())
			num += 1

		# Sign transaction
		trans = self.tx.sign_transaction(self.txtPrivateKey.toPlainText())
		
	def cancel(self):
		self.close()


