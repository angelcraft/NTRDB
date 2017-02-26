from urllib.request import urlopen, build_opener
from urllib.parse import urlencode
from urllib.error import HTTPError
import exceptions


def test_login():
    url = 'http://127.0.0.1:8080/login'
    data = urlencode({'rtype': 'loginpg',
                      'email': 'test@test.test',
                      'pword': 'test'
                      }).encode('utf-8')
    content = urlopen(url=url, data=data)
    cookies = content.getheader('Set-Cookie')
    if not 'AToken' in cookies:
        raise exceptions.NoCookieReceived()
    else:
        assert True


def test_pluginmgmt():
    url = 'http://127.0.0.1:8080/login'
    data = urlencode({'rtype': 'loginpg',
                      'email': 'test@test.test',
                      'pword': 'test'
                      }).encode('utf-8')
    content = urlopen(url=url, data=data)
    cookies = content.getheader('Set-Cookie')
    if 'AToken' not in cookies:
        raise exceptions.NoCookieReceived()
    else:
        opener = build_opener()
        opener.addheaders.append(('Cookie', cookies))
    addtest = opener.open(
        'http://127.0.0.1:8080/additem?name=Test+plugin&desc=Test&ver=0&developer=Developer&tid=00040000001A3200%3B00040000001A4100&devsite=http%3A%2F%2Fexample.com&link=http%3A%2F%2Fexample.com%2Fplg&pic=&ctype=universal&add=1')
    if not 'Your plugin were added to base. Now you need to wait for moderator to approve it.' in str(addtest.read(), 'utf-8'):
        raise exceptions.BadPage
    del addtest
    edittest = opener.open(
        'http://127.0.0.1:8080/edit?edit=1&plugid=1&name=Test+plugin+edited&desc=Test&ver=0&developer=Developer&tid=00040000001A3200%3B00040000001A4100&devsite=http%3A%2F%2Fexample.com&link=http%3A%2F%2Fexample.com%2Fplg&pic=&ctype=universal&add=1')
    if not "Your plugin was edited successfully" in str(edittest.read(), 'utf-8'):
        raise exceptions.BadPage
    del edittest
    rmtest = opener.open('http://127.0.0.1:8080/rm?plugid=1&sure=1')
    if not 'Your plugin was removed' in str(rmtest.read(), 'utf-8'):
        raise exceptions.BadPage
    del rmtest
    assert True