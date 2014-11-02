
import sys, json, os.path
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from binascii import hexlify, unhexlify
from bip32 import *
from rawtx import *
from sign_single import *
from gen_master_key import *
from gen_hardened_childkey import *

class console(QMainWindow):
    
	def __init__(self):
		super(console, self).__init__()
		self.setStyleSheet("QLabel { font-family: Droid Dans; font-size: 10pt; color: #333; } QApplication { background: #ddd; }")
		self.initUI()

	def initUI(self):

		## Define tab control
		tabControl = QTabWidget()
		tabControl.addTab(self.ui_tab_import_txs(), 'Import Raw Txs')
		tabControl.addTab(self.ui_tab_sign_singletx(), 'Sign Single Tx')
		tabControl.addTab(self.ui_tab_sign_multisig(), 'Multisig Sign')
		self.setCentralWidget(tabControl)

		# Menu bar
		self.ui_menubar()

		# Status bar
		self.statusBar().showMessage('Ready')

		# Display form
		#self.resize(600, 300)
		self.setMinimumWidth(700)
		self.center()
		self.setWindowTitle('Offline Tx Signer')
		self.show()

	def ui_menubar(self):

		# Initialize
		menubar = self.menuBar()

		# Define exit action
		exitAction = QAction(QIcon('exit.png'), '&Exit', self)
		exitAction.setShortcut('Ctrl+Q')
		exitAction.setStatusTip('Exit application')
		exitAction.triggered.connect(self.close)

		# Define menu bar
		fileMenu = menubar.addMenu('&File')
		fileMenu.addAction(exitAction)

		# Keys menu
		keysMenu = menubar.addMenu('&BIP32 Keys')
		genMasterKeyAction = QAction('Generate Master Key', self)
		genChildKeyAction = QAction('Generate Hardened Child Key', self)
		keysMenu.addAction(genMasterKeyAction)
		keysMenu.addAction(genChildKeyAction)

		# Keys menu - connects
		genMasterKeyAction.triggered.connect(self.gen_master_key)
		genChildKeyAction.triggered.connect(self.gen_hardened_childkey)
		

	def ui_tab_import_txs(self):

		# Initialize
		tab = QWidget()
		layout = QGridLayout()
		layout.setAlignment(Qt.AlignTop)

		# Header
		lblHeader = QLabel('Import Transactions')
		lblHeader.setStyleSheet("font-size: 14pt; font-weight: bold; margin-bottom: 5px;")

		# Description
		lblDescription = QLabel('You may import a JSON file of raw transactions, and have them automatically signed by selecting the file below and entering your BIP32 private key.  You will receive a new JSON file in return, which you must upload to your online system to complete the sends.')
		lblDescription.setStyleSheet("margin-bottom: 5px;")
		lblDescription.setWordWrap(True)

		# Select file button
		self.lblImportFilename = QLabel('No File')
		self.buttonSelectJSONFile = QPushButton('Select File...')
		self.buttonSelectJSONFile.setMaximumWidth(150)
		self.buttonSelectJSONFile.clicked.connect(self.select_json_file)

		# Textboxes
		self.txtImportPrivKey = QPlainTextEdit()
		self.txtImportPrivKey.setMaximumHeight(60)

		# Push button
		buttonImportTxs = QPushButton('Import Transactions', self)
		buttonImportTxs.setMaximumWidth(250)
		buttonImportTxs.clicked.connect(self.import_txs)

		# Add widgets to layout
		layout.addWidget(lblHeader, 0, 0, 1, 3, Qt.AlignTop)
		layout.addWidget(lblDescription, 1, 0, 1, 3, Qt.AlignTop)
		layout.addWidget(QLabel('JSON File:  '), 2, 0, Qt.AlignTop)
		layout.addWidget(self.lblImportFilename, 2, 1, Qt.AlignLeft)
		layout.addWidget(self.buttonSelectJSONFile, 2, 2, Qt.AlignLeft)
		layout.addWidget(QLabel('BIP32 Private Key:  '), 3, 0, Qt.AlignTop)
		layout.addWidget(self.txtImportPrivKey, 3, 1, 1, 2, Qt.AlignTop)
		layout.addWidget(buttonImportTxs, 4, 2, 1, 1, Qt.AlignRight)
		tab.setLayout(layout)

		# Return
		return tab


	def ui_tab_sign_singletx(self):

		# Initialize
		tab = QWidget()
		layout = QGridLayout()
		layout.setAlignment(Qt.AlignTop)

		# Header
		lblHeader = QLabel("Sign Single Transaction")
		lblHeader.setStyleSheet("font-size: 14pt; font-weight: bold; margin-bottom: 10px;")

		# Description
		lblDescription = QLabel('You may sign an individual transaction by entering the raw hex code of the transaction below.  This is the same hex code as the createrawtransaction() function from bitcoind will provide.')
		lblDescription.setStyleSheet("margin-bottom: 10px;")
		lblDescription.setWordWrap(True)

		# Text box
		self.txtRawHexCode = QPlainTextEdit()
		self.txtRawHexCode.setMaximumHeight(80)

		# Push button
		buttonSignSingleTx = QPushButton('Sign Single Transaction', self)
		buttonSignSingleTx.setMaximumWidth(250)
		buttonSignSingleTx.clicked.connect(self.sign_single_tx)

		# Add to layout
		layout.addWidget(lblHeader, 0, 0, 1, 2, Qt.AlignTop)
		layout.addWidget(lblDescription, 1, 0, 1, 2, Qt.AlignTop)
		layout.addWidget(QLabel('Hex Code:  '), 2, 0, Qt.AlignTop)
		layout.addWidget(self.txtRawHexCode, 2, 1, Qt.AlignTop)
		layout.addWidget(buttonSignSingleTx, 3, 1, 1, 1, Qt.AlignRight)
		tab.setLayout(layout)

		# Return
		return tab


	def ui_tab_sign_multisig(self):

		# Initialize
		tab = QWidget()
		layout = QGridLayout()
		layout.setAlignment(Qt.AlignTop)

		# Header
		lblHeader = QLabel("Sign Multisig Transaction")
		lblHeader.setStyleSheet("font-size: 14pt; font-weight: bold; margin-bottom: 10px;")

		# Description
		lblDescription = QLabel('Coming soon!')
		lblDescription.setStyleSheet("margin-bottom: 10px;")
		lblDescription.setWordWrap(True)

		# Add to layout
		layout.addWidget(lblHeader, 0, 0, 1, 2, Qt.AlignTop)
		layout.addWidget(lblDescription, 1, 0, 1, 2, Qt.AlignTop)
		tab.setLayout(layout)

		# Return
		return tab

	def gen_master_key(self, event):
		form = gen_master_key(self)
		form.exec_()

	def gen_hardened_childkey(self, event):
		form = gen_hardened_childkey(self)
		form.exec_()
		
	def select_json_file(self, event):
		filename = QFileDialog.getOpenFileName(self, "Open Transaction File", "", "JSON files (*.*)")
		self.lblImportFilename.setText(filename)

	def import_txs(self, event):

		# Initial checks
		if self.lblImportFilename.text() == '' or not os.path.isfile(self.lblImportFilename.text()):
			QMessageBox.critical(self, "Error", "You did not specify a valid JSON file.  Please ensure you select a JSON file, and try again.")
			return

		# Get json code
		fh = open(self.lblImportFilename.text(), 'r')
		try:
			j = json.load(fh)
		except:
			QMessageBox.critical(self, "Error", "Unable to load JSON file.  Please ensure the JSON file is correctly formatted, and try again.")
			return
		fh.close()

		# Validate private key
		privkey = str(self.txtImportPrivKey.toPlainText())
		#privkey = 'tprv8dxkXXLevuHXR3tLvBkaDLyCnQxsQQVafnDMEQNds8r8tjSPfNTGD5ShtpP8QeTdtCoWGmrMC5gs9j7ap8ATdSsAD2KCv87BGdzPWwmdJt2'
		b32 = bip32()
		if b32.validate_ext_private_key(privkey) == False:
			QMessageBox.critical(self, "Error", "You did not specify a valid BIP32 private key.  Please double check, and try again.")
			return

		# Set variables
		if 'wallet_id' in j:
			results['wallet_id'] = j['wallet_id']
		txfee = 0.0001 if not 'txfee' in j else float(j['txfee'])
		txfee_paidby = 'sender' if not 'txfee_paidby' in j else j['txfee_paidby']
		results = {'tx': [], 'spent_inputs': [], 'change_inputs': [] }

		# Go through outputs
		for out in j['outputs']:
			
			# Initialize
			tx = rawtx()
			tx.__init__()

			# Blank variables
			amount = 0
			has_change = False
			change_id = 0
			change_input = { }

			# Add output
			out_amount = float(out['amount']) if not txfee_paidby == 'recipient' else float(out['amount']) - txfee
			tx.add_output(out_amount, out['address'])

			# Go through inputs
			while len(j['inputs']) > 0:
				item = j['inputs'].pop(0)
				tx.add_input(unhexlify(item['txid']), int(item['vout']), unhexlify(item['sigscript']), item['keyindex'])
				amount += float(item['amount'])

				# Mark input spent
				results['spent_inputs'].append(item)

				# Check amount
				if amount >= float(out['amount']) + txfee:
					change_amount = float(amount) - out_amount
					if txfee_paidby == 'sender':
						change_amount -= txfee

					if change_amount > float(0):

						# Add output
						b32 = bip32()
						if 'change_keyindex' in item:
							change_keyindex = item['change_keyindex']
						elif 'change_keyindex' in j and j['change_keyindex'] != 'source_address':
							change_keyindex = j['change_keyindex']
						else:
							change_keyindex = item['keyindex']

						# Add change output
						change_addr = b32.key_to_address(b32.derive_child(privkey, change_keyindex))
						tx.add_output(change_amount, change_addr)

						# Set change input variables
						has_change = True
						change_id += 1
						change_input['input_id'] = 'c' + str(change_id)
						change_input['vout'] = 1
						change_input['amount'] = change_amount
						change_input['address'] = change_addr
						change_input['keyindex'] = item['change_keyindex']
						change_input['change_keyindex'] = item['change_keyindex']

						# Get sig script
						daddr = hexlify(b58decode(change_addr, None))
						if daddr[:2] == 'c4' or daddr[:2] == '05':
							change_input['sigscript'] = 'a914' + daddr[2:42] + '87'
						else:
							change_input['sigscript'] = '76a914' + daddr[2:42] + '88ac'
						
					break

			# Sign transaction
			trans = tx.sign_transaction(privkey)
			txid = hashlib.sha256(hashlib.sha256(unhexlify(trans)).digest()).hexdigest()
			output_id = 0 if not 'output_id' in out else out['output_id']
			results['tx'].append({ 'output_id': str(output_id), 'txid': txid, 'amount' : out['amount'], 'to_address': out['address'], 'hexcode': trans })

			# Add change input, if needed
			if has_change == True:
				change_input['txid'] = txid
				results['change_inputs'].append(change_input)
				j['inputs'].append(change_input)

		# Save JSON file
		save_filename = QFileDialog.getSaveFileName(self, "Save Transaction File", "signedtx.json", "JSON files (*.*)")
		if save_filename != '':
			with open(save_filename, 'w') as outfile:
				json.dump(results, outfile)

		QMessageBox.information(self, 'JSON File Saved', "The new JSON file of signed transactions has been successfully saved.  Please copy this file to your online computer, and upload it into the online software.")

	def sign_single_tx(self, event):

		# Decode transaction
		tx = rawtx()
		if tx.decode_transaction(str(self.txtRawHexCode.toPlainText())) == False:
			QMessageBox.warning(self, "Error", "Invalid hexidecimal transaction code specified.  Please double check, and try again.")
			return

		# Display form
		form = sign_single(self, self.txtRawHexCode.toPlainText())
		form.exec_()

	def center(self):
		qr = self.frameGeometry()
		cp = QDesktopWidget().availableGeometry().center()
		qr.moveCenter(cp)
		self.move(qr.topLeft())

	def closeEventOld(self, event):
		reply = QMessageBox.question(self, 'Message', "Are you sure to quit?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

		if reply == QMessageBox.Yes:
			event.accept()
		else:
			event.ignore()        
        

