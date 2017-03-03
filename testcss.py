from urllib.request import urlopen
err = 0
for i in range(10000):
    print("Test #", i)
    t = urlopen('http://127.0.0.1:8080/bstheme.css')
    t = str(t.read(), 'utf-8')
    if not t.startswith('/*!'):
        print("Ducked up")
        print(t)
        err = err + 1
print("Failed CSS loading:", err)