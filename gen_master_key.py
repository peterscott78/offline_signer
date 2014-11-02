
import sys
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from bip32 import *

class gen_master_key(QDialog):

	def __init__(self, parent = None):
		QDialog.__init__(self, parent)
		self.ui = gen_master_key
		self.ui.initUI(self)

	def initUI(self):

		# Initialize
		self.setWindowTitle('Generate Master BIP32 Key')
		self.setMinimumWidth(700)
		layout = QGridLayout()

		# Header
		lblHeader = QLabel('Generate Master BIP32 Key')
		lblHeader.setStyleSheet("font-size: 14pt; font-weight: bold;")

		# Description
		lblDescription = QLabel('You may generate new master BIP32 key pairs by pressing the below button.  All keys are genererated with a random 8192 bit key.  The private key should ALWAYS remain offline, whereas you will most likely need the public key for your online software system.')
		lblDescription.setStyleSheet("margin-bottom: 10px;")
		lblDescription.setWordWrap(True)

		# Testnet radio buttons
		boxTestnet = QGroupBox()
		layoutTestnet = QHBoxLayout()
		self.radioTestnetYes = QRadioButton('Yes')
		self.radioTestnetNo = QRadioButton('No')
		self.radioTestnetNo.setChecked(True)
		layoutTestnet.addWidget(self.radioTestnetYes, 0, Qt.AlignTop)
		layoutTestnet.addWidget(self.radioTestnetNo, 1, Qt.AlignTop)
		boxTestnet.setStyleSheet("margin-top: -5px; padding: 0; border: 0;")
		boxTestnet.setLayout(layoutTestnet)

		# Textboxes
		self.txtMasterPrivKey = QPlainTextEdit()
		self.txtMasterPrivKey.setMaximumHeight(60)
		self.txtMasterPrivKey.setReadOnly(True)
		self.txtMasterPrivKey.setStyleSheet("background: #ccc;")
		self.txtMasterPubKey = QPlainTextEdit()
		self.txtMasterPubKey.setMaximumHeight(60)
		self.txtMasterPubKey.setReadOnly(True)
		self.txtMasterPubKey.setStyleSheet("background: #ccc;")

		# Push button
		buttonGenMasterKey = QPushButton('Generate Master Key', self)
		buttonGenMasterKey.setMinimumWidth(250)
		buttonGenMasterKey.clicked.connect(self.ok)

		# Add widgets to layout
		layout.addWidget(lblHeader, 0, 0, 1, 2, Qt.AlignTop)
		layout.addWidget(lblDescription, 1, 0, 1, 2, Qt.AlignTop)
		layout.addWidget(QLabel('Testnet?:  '), 2, 0, Qt.AlignTop)
		layout.addWidget(boxTestnet, 2, 1, Qt.AlignTop)
		layout.addWidget(QLabel('Private Key:  '), 3, 0, Qt.AlignTop)
		layout.addWidget(self.txtMasterPrivKey, 3, 1, Qt.AlignTop)
		layout.addWidget(QLabel('Public Key:  '), 4, 0, Qt.AlignTop)
		layout.addWidget(self.txtMasterPubKey, 4, 1, Qt.AlignTop)
		layout.addWidget(buttonGenMasterKey, 5, 1, Qt.AlignRight)

		# Display dialog
		self.setLayout(layout)
		self.show()

	def ok(self):

		# Initialize
		testnet = self.radioTestnetYes.isChecked()
		b32 = bip32(testnet)
		
		# Generate master key
		privkey = b32.generate_master_key()
		pubkey = b32.ext_private_to_public(privkey)

		# Set textboxes
		self.txtMasterPrivKey.setPlainText(privkey)
		self.txtMasterPubKey.setPlainText(pubkey)


	def cancel(self):
		self.close()

