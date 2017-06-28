#Burp Parser XML to CSV
#Simple, Easy to Use 


from BeautifulSoup import BeautifulSoup
import csv
import os
import random
import base64


while(True):
    # ctrl-c to quit

	print "Welcome to Burp XML Simple Parse. \n 1 -------- Current Directory \n 2 -------- Enter Path to XML File "
	Uinput = raw_input("Enter choose: ")

	if Uinput == "2":
		filePath = raw_input('Enter Burp XML File Location: ')
		soup = BeautifulSoup(open(filePath,'r'))
	elif Uinput == "1":
		fileName = raw_input("Enter the BURRP XML filename (sample.xml): ")
		dir_path = os.path.dirname(os.path.realpath(__file__)) + "\\"
		filePath = dir_path + fileName
		soup = BeautifulSoup(open(filePath,'r'))

	else:
		print "ERROR - Please choose from the menu options"
		break

	issues = soup.findAll('issue')

	
	issueOutput =[]
	for i in issues:
		name = i.find('name').text
		host = i.find('host')
		ip = host['ip']
		host = host.text
		path = i.find('path').text
		location = i.find('location').text
		severity = i.find('severity').text
		confidence = i.find('confidence').text

		issueBackground = i.find('issuebackground').text.replace("<p>","").replace("</p>","")
		remediationBackground = i.find('remediationbackground').text.replace("<p>","").replace("</p>","")
		vulnerabilityClassification = i.find('vulnerabilityclassifications').text.replace("<ul>","").replace("</ul>","").replace("\n","")
		request = base64.b64decode(i.find('requestresponse').find('request').text)
		response = base64.b64decode(i.find('requestresponse').find('response').text)
		issueDetail = i.find('issuedetail').text
		

		
		result = (name, host, ip, location, severity, confidence, issueBackground, remediationBackground, vulnerabilityClassification, issueDetail, request, response)
		issueOutput.append(result)

		#print filePath

	#rando = random.randint(2000,3000)
	#filenameout = "BurpOutput %s" % rando


	outfile = open("burpOutput.csv","wb")
	writer = csv.writer(outfile)
	writer.writerow(["Name","Host","IP","Path","Severity","Confidence","Issue Background","Remediation Background","Vulnerability Classification", "Issue Details", "Request", "Response"])
	writer.writerows(issueOutput)

	
	end = raw_input("File Complete! Want to end session? (Y/N)" )

	if end == "Y":
		break



