import requests
 
url = "http://challenge-dbe00efd0051171f.sandbox.ctfhub.com:10800/flag_in_here/"

def flagUrl():
    for i in range(5):
        for j in range(5):
            url_final = url + "/" + str(i) + "/" + str(j)
            r = requests.get(url_final)
            r.encoding = "utf-8"
            get_file=r.text
            if "flag.txt" in get_file:
                return url_final
    return ""

if __name__ == '__main__':
    url = flagUrl() + "/" + "flag.txt"
    s = requests.session()
    print(s.get(url).text)