#!/usr/bin/python
import jwt
import sys
import json
import requests

#VARIABLES
secret_JWT= 'gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE'
payload= {'name':'theadmin'}


#main
if (len(sys.argv)!=2):
    print("usage: python api_log.py \'command\' ")
    sys.exit(1)

#pillem el payload
try:
    command = 'a |'+str(sys.argv[1])

except:
    print('Wrong payload. Exiting...')
    sys.exit(1)



#crea un token JWT
token_jwt = jwt.encode(payload,secret_JWT,algorithm='HS256').decode('utf-8')


#fem les request a la API
url = 'http://10.10.11.120:3000/api/logs?file='+command
print('\nSending request:')

print('+   URL: '+url)

try:
    r = requests.get(url,headers={'auth-token':token_jwt})
    print('\nGot response with status code ['+str(r.status_code)+']: ')

    #si tenim un resultat amb salts de linia el printem correctament
    if '\\n' in r.text:
        rsplit= r.text.split('\\n')
        for l in rsplit:
            print(l)

    else:
        print(r.text)

except:
    print('\nSomething went wrong...')
