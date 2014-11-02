
import sys
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from bip32 import *

class gen_hardened_childkey(QDialog):

	def __init__(self, parent = None):
		QDialog.__init__(self, parent)
		self.ui = gen_hardened_childkey
		self.ui.initUI(self)

	def initUI(self):

		# Initialize
		self.setWindowTitle('Generate Hardened Child Key')
		self.setMinimumWidth(700)
		layout = QGridLayout()

		# Header
		lblHeader = QLabel('Generate Hardened Child Key')
		lblHeader.setStyleSheet("font-size: 14pt; font-weight: bold;")

		# Description
		lblDescription = QLabel('This allows you to generate "hardened" child keys, which is meant if you are using the hierarchial nature of BIP32 wallets, and will be handing out private keys to other people (eg.  employees, family, etc.).  Please see the help file for more details.  To continue, enter your existing BIP32 private key, and the desired key index below.');
		lblDescription.setStyleSheet("margin-bottom: 10px;")
		lblDescription.setWordWrap(True)

		# Textboxes
		self.txtMasterPrivKey = QPlainTextEdit()
		self.txtMasterPrivKey.setMaximumHeight(60)
		self.txtKeyIndex = QLineEdit()
		self.txtKeyIndex.setMaximumWidth(80)
		self.txtChildPrivKey = QPlainTextEdit()
		self.txtChildPrivKey.setMaximumHeight(60)
		self.txtChildPrivKey.setReadOnly(True)
		self.txtChildPrivKey.setStyleSheet("background: #ccc;")
		self.txtChildPubKey = QPlainTextEdit()
		self.txtChildPubKey.setMaximumHeight(60)
		self.txtChildPubKey.setReadOnly(True)
		self.txtChildPubKey.setStyleSheet("background: #ccc;")

		# Push button
		buttonGenChildKey = QPushButton('Generate Hardened Child Key', self)
		buttonGenChildKey.setMinimumWidth(300)
		buttonGenChildKey.clicked.connect(self.ok)

		# Add widgets to layout
		layout.addWidget(lblHeader, 0, 0, 1, 2, Qt.AlignTop)
		layout.addWidget(lblDescription, 1, 0, 1, 2, Qt.AlignTop)
		layout.addWidget(QLabel('BIP32 Private Key:  '), 2, 0, Qt.AlignTop)
		layout.addWidget(self.txtMasterPrivKey, 2, 1, Qt.AlignTop)
		layout.addWidget(QLabel('Key Index (no \' mark):'), 3, 0, Qt.AlignTop)
		layout.addWidget(self.txtKeyIndex, 3, 1, Qt.AlignTop)
		layout.addWidget(QLabel('Child Private Key:  '), 4, 0, Qt.AlignTop)
		layout.addWidget(self.txtChildPrivKey, 4, 1, Qt.AlignTop)
		layout.addWidget(QLabel('Child Public Key:  '), 5, 0, Qt.AlignTop)
		layout.addWidget(self.txtChildPubKey, 5, 1, Qt.AlignTop)
		layout.addWidget(buttonGenChildKey, 6, 1, Qt.AlignRight)

		# Display dialog
		self.setLayout(layout)
		self.show()

	def ok(self):

		# Initialize
		b32 = bip32(False)
		
		# Generate master key
		privkey = b32.derive_child(self.txtMasterPrivKey.toPlainText(), self.txtKeyIndex.text(), True)
		pubkey = b32.ext_private_to_public(privkey)

		# Set textboxes
		self.txtChildPrivKey.setPlainText(privkey)
		self.txtChildPubKey.setPlainText(pubkey)


	def cancel(self):
		self.close()

