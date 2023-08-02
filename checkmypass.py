import requests
import hashlib
import sys

def request_api_data(query_char):
	url = "https://api.pwnedpasswords.com/range/" + query_char # Eg: 'ABCDE' in place of query_char(here only first 5 char of hashed paswords are used)
	res = requests.get(url) # Sends a GET request to url
	# print(res) #Response[200] means OK success status || Response[400] means Bad Request response status

	if res.status_code != 200:
		raise RuntimeError(f'Error Fetching: {res.status_code}, Check the api and try again!')
	return res 

# def read_response(response):
# 	print(response.text) # Will give all the hashes that match the beginning of the hashed password

def get_pass_leak_count(hashes, hash_to_check):
	hashes = (line.split(":") for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0

def pwned_api_check(password):
	#Check password if it exists in API response
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5_char, tail = sha1password[:5], sha1password[5:]
	response = request_api_data(first5_char)
	#print(response)
	return get_pass_leak_count(response, tail)

def main(args):
	for password in args:
		count = pwned_api_check(password)
		if count:
			print(f'{password} was found {count} times... Please change your password!')
		else:
			print(f'{password} was NOT found ... GREAT JOB!')
	return 'Done!'

if __name__ == '__main__':
	run_function = main(sys.argv[1:])
	sys.exit(run_function) # To exit the process
