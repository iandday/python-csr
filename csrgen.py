#!/usr/bin/env python
# python-csr
# Generate a key and certificate request to receive a StartSSL signed certificate.
# Final created directory will contain:
# 	private key file
# 	CSR file
# 	StartSSL signed certificates
# 	PKCS12 certificate suitable for use by Sophos UTM.
#
# Forked from: https://github.com/cjcotton/python-csr
#
# Usage: csrgen [fqdn]
# Author: Ian Day <iandday@gmail.com> 20160122




# Modules
from OpenSSL import crypto, SSL
from cStringIO import StringIO
import os
import shutil
import argparse
import zipfile
import getpass
import time


def generateCSR(nodename):
	'''Generates certificate signing request to submit to StartSSL
	   Modify below variables before running script
	   Country
	   State
	   Location
	   Organization
	   Organizationl Unit'''
	C  = 'US'          
	ST = 'Ohio'       
	L  = 'Columbus'   
	O  = 'Daynet'      
	OU = 'Daynet'
	csrfile = str(nodename) + '.csr'
	keyfile = str(nodename) + '.key'
	TYPE_RSA = crypto.TYPE_RSA
	req = crypto.X509Req()
	req.get_subject().CN = nodename
	req.get_subject().countryName = C
	req.get_subject().stateOrProvinceName = ST
	req.get_subject().localityName = L
	req.get_subject().organizationName = O
	req.get_subject().organizationalUnitName = OU
	# Add in extensions
	base_constraints = ([
        crypto.X509Extension("keyUsage", False, "Digital Signature, Non Repudiation, Key Encipherment"),
        crypto.X509Extension("basicConstraints", False, "CA:FALSE"),])
	x509_extensions = base_constraints
	req.add_extensions(x509_extensions)
	key = generateKey(TYPE_RSA, 2048)
	req.set_pubkey(key)
	req.sign(key, "sha1")
	generateFiles(csrfile, req)
	generateFiles(keyfile, key)
	return req

	
def generateKey(type, bits):
	'''Generates private key for CSR generation'''
	key = crypto.PKey()
	key.generate_key(type, bits)
	return key
    

def generateFiles(mkFile, request):
	'''Generates CSR file and private key file used to generate CSR'''
	if mkFile == str(args.name) + '.csr':
		f = open(mkFile, "w")
		f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, request))
		f.close()
		print ("CSR below, copy and paste into StartSSL's certificates wizard\n")
		print crypto.dump_certificate_request(crypto.FILETYPE_PEM, request)
	elif mkFile == str(args.name) + '.key':
		f = open(mkFile, "w")
		f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, request))
		f.close()
	else:
		print "Failed."
		exit()

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("name", help="Provide the FQDN", action="store")
	args = parser.parse_args()

	date = time.strftime('%Y%m%d')
	fileName = args.name + '_' + str(date)

	generateCSR(args.name)
	wait = raw_input('Place zip file downloaded from StartSSL in same directory as script and press any key to continue')

	#Extract nested zip file containging certificate chain
	certPackage = zipfile.ZipFile(args.name + '.zip', 'r')
	certPackageData = StringIO(certPackage.read('OtherServer.zip'))
	otherCertZip = zipfile.ZipFile(certPackageData)

	#Concatenante certificate with intermediate and root certificate
	rootCert = otherCertZip.read('root.crt', 'r')
	intermediateCert = otherCertZip.read('1_Intermediate.crt', 'r')
	finalCert = otherCertZip.read('2_' +  args.name +'.crt', 'r')
	concatCert = finalCert + intermediateCert + rootCert
	certOut = open(fileName + '.crt', "w")
	certOut.write(concatCert)
	certOut.close()

	#Generate PKCS12 certificate
	pk12Cert = crypto.PKCS12()
	keyFile=open(args.name + '.key', 'rt').read()
	key=crypto.load_privatekey(crypto.FILETYPE_PEM, keyFile)
	pk12Cert.set_privatekey(key)
	cert=crypto.load_certificate(crypto.FILETYPE_PEM, concatCert)
	pk12Cert.set_certificate(cert)
	pk12CertFile = open(fileName + '.pfx', 'wb')
	certPass = getpass.getpass('Password for PKCS12 file: ')
	pk12CertFile.write(pk12Cert.export(passphrase=certPass))
	pk12CertFile.close()

	#Create subdirectroy for host and move all generated and downloaded files
	os.mkdir(fileName)
	shutil.move(fileName + '.pfx', fileName + '/' + fileName + '.pfx')
	shutil.move(fileName + '.crt', fileName + '/' + fileName + '.crt')
	shutil.move(args.name + '.key', fileName + '/' + args.name + '.key')
	shutil.move(args.name + '.csr', fileName + '/' + args.name + '.csr')
	shutil.move(args.name + '.zip', fileName + '/' + args.name + '.zip')


