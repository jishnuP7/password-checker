import requests
import hashlib
#import sys

#To Check Password is Strong or not
def request_api_data(password_chara):      
	url='http://api.pwnedpasswords.com/range/'+password_chara
	res=requests.get(url)
	if res.status_code!=200:
		raise RuntimeError(f'Error Fetched {res.status_code},check the api try again')
	else:
		return res
'''
def read_passwords(res):
	print(res.text)
'''
#To get the number of times this password is hacked
def get_password_leak_count(response,response_tocheck):
	hashes=(line.split(":") for line in response.text.splitlines())
	for hash,count in hashes:
		if hash == response_tocheck:
			return count
	return 0


def pwned_api_check(password):
	#print(password.encode('utf-8'))
	sha_pass=hashlib.sha1(password.encode('utf-8')).hexdigest().upper() #Changing the password into strong hexadecimal string
	first5_char,tail=sha_pass[:5],sha_pass[5:]
	response=request_api_data(first5_char)
	#print(first5_char)
	return get_password_leak_count(response,tail)


def main(password):
	count=pwned_api_check(password)
	if count:
		print(f'{password} was found {count} times, you should probably change the password')
	else:
		print(f'{password} not found, carry on!!')

	'''
	for password in args:

		if count:
			print(f'{password} was found {count} times, you should probably change the password')
		else:
			print(f'{password} not found, carry on!!') 
			'''

if __name__=='__main__':
	main('hello')
	print('done')

