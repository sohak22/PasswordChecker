import requests 
import hashlib
import sys



def request_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	res = requests.get(url)
	if res.status_code !=200:
		raise RuntimeError(f'Error fetching:{res.status_code}, check the api and try again') #Check if api is working 
	return res

def get_password_leaks_count(hashes, hash_to_check):  #recieves the hashes and checks through them 
	hashes = (line.split(':') for line in hashes.text.splitlines()) #Tuple comprehension, 
	for h, count in hashes:
		if h == hash_to_check: #if the hash is the same is the same as the tail (hash password) return how many times it has been leaked
			return count
	return 0


def pwned_api_check(password):  
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper() #Encodes and creates SHA1 object with this in hexadecimal format 
	first5_char, tail = sha1password[:5], sha1password[5:] #Store first 5 and remaining characters in variables, to easlily request data 
	response = request_api_data(first5_char)
	print(response)
	return get_password_leaks_count(response, tail) #tail is the 'hash to check'

def main(args): #Recieves the passowrds we want to check 
	for password in args:
		count= pwned_api_check(password)
		if count:
			print(f'{password} was found {count} times, it is suggested you change your password.')
		else:
			print(f'{password} was NOT found. Continue with use of password.')
		return 'done!'

if __name__ == '__main__': #only run if it is the main file not being imported 
	sys.exit(main(sys.argv[1:])) #accepts the passwords we want it too and exits the process

