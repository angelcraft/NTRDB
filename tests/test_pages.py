from urllib.request import urlopen, build_opener
from urllib.parse import urlencode
from urllib.error import HTTPError
import exceptions


def login():
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
        return opener


def test_thm():
    opener = login()
    managetest = opener.open('http://127.0.0.1:8080/themes')
    if not "Themes" in str(managetest.read(), 'utf-8'):
        raise exceptions.BadPage
    else:
        assert True


def test_mg():
    opener = login()
    managetest = opener.open('http://127.0.0.1:8080/manageitems')
    if not "Manage your plugins" in str(managetest.read(), 'utf-8'):
        raise exceptions.BadPage
    else:
        assert True


def test_index():
    assert 'WELCOME TO NTR PLUGIN DATABASE' in str(
        urlopen('http://127.0.0.1:8080/index').read(), 'utf-8').upper()


def test_addplgpg():
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
        opener.open('http://127.0.0.1:8080/additem')
        assert True
